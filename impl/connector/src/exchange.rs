//! Protocole d'échange de blocs — id `protocols.echange-blocs`, partie
//! `connector` : client libp2p (identité éphémère, aucune écoute), session
//! authentifiée auprès du Nœud, lecture de secours chez les partenaires,
//! délégation, et branchements réseau de `BlockSource` / `ReplaySink`.
//! Réf. spec : docs/04-protocols/echange-blocs.md.

use std::collections::HashMap;
use std::time::Duration;

use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{self, OutboundRequestId, ProtocolSupport};
use libp2p::swarm::SwarmEvent;
use libp2p::{identity, noise, tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm};
use p2p_storage_core::k_attach::derive_k_attach_as_user;
use p2p_storage_core::CoreError;
use p2p_storage_protocol::exchange::*;
use tokio::sync::{mpsc, oneshot};

use crate::integrity::{BlockHash, BlockSource};
use crate::write_queue::{Op, Queued, ReplaySink};

/// Erreurs du client.
#[derive(Debug, thiserror::Error)]
pub enum ExchangeError {
    #[error("réseau : {0}")]
    Network(String),
    #[error("adresse sans /p2p/<PeerId>")]
    NoPeerId,
    #[error("refus : {0}")]
    Refused(#[from] Refusal),
    #[error("réponse inattendue")]
    Unexpected,
    #[error(transparent)]
    Core(#[from] CoreError),
    #[error("client arrêté")]
    Stopped,
}

// ------------------------------------------------------------------ codec

#[derive(Debug, Clone)]
enum Frame {
    Data(Vec<u8>),
    TooLarge,
}

#[derive(Debug, Clone, Default)]
struct FrameCodec;

async fn read_frame<T: futures::AsyncRead + Unpin + Send>(io: &mut T) -> std::io::Result<Frame> {
    let mut len = [0u8; 4];
    io.read_exact(&mut len).await?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_MESSAGE_BYTES {
        return Ok(Frame::TooLarge);
    }
    let mut buf = vec![0u8; n];
    io.read_exact(&mut buf).await?;
    Ok(Frame::Data(buf))
}

async fn write_frame<T: futures::AsyncWrite + Unpin + Send>(
    io: &mut T,
    f: Frame,
) -> std::io::Result<()> {
    let Frame::Data(d) = f else {
        return Err(std::io::ErrorKind::InvalidInput.into());
    };
    io.write_all(&(d.len() as u32).to_be_bytes()).await?;
    io.write_all(&d).await?;
    io.close().await
}

#[async_trait::async_trait]
impl request_response::Codec for FrameCodec {
    type Protocol = StreamProtocol;
    type Request = Frame;
    type Response = Frame;

    async fn read_request<T>(&mut self, _: &StreamProtocol, io: &mut T) -> std::io::Result<Frame>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        read_frame(io).await
    }

    async fn read_response<T>(&mut self, _: &StreamProtocol, io: &mut T) -> std::io::Result<Frame>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        read_frame(io).await
    }

    async fn write_request<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        f: Frame,
    ) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        write_frame(io, f).await
    }

    async fn write_response<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        f: Frame,
    ) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        write_frame(io, f).await
    }
}

// ----------------------------------------------------------------- client

type Reply = oneshot::Sender<Result<Response, ExchangeError>>;
type Behaviour = request_response::Behaviour<FrameCodec>;

/// Client d'échange : identité **éphémère** tirée au démarrage, mode
/// sortant seul (le Connecteur n'accepte aucune connexion entrante).
#[derive(Clone)]
pub struct BlockClient {
    peer_id: PeerId,
    tx: mpsc::Sender<Box<(Multiaddr, Request, Reply)>>,
}

impl BlockClient {
    pub fn start() -> Result<Self, ExchangeError> {
        let net = |e: &dyn std::fmt::Display| ExchangeError::Network(e.to_string());
        let keypair = identity::Keypair::generate_ed25519();
        let peer_id = keypair.public().to_peer_id();
        let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| net(&e))?
            .with_behaviour(|_| {
                request_response::Behaviour::<FrameCodec>::new(
                    [(StreamProtocol::new(PROTOCOL), ProtocolSupport::Outbound)],
                    request_response::Config::default()
                        .with_request_timeout(Duration::from_secs(30)),
                )
            })
            .map_err(|e| net(&e))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();
        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(run(swarm, rx));
        Ok(Self { peer_id, tx })
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Envoie une requête (`addr` suffixée de `/p2p/<PeerId>`).
    pub async fn request(&self, addr: Multiaddr, req: Request) -> Result<Response, ExchangeError> {
        let (r, rx) = oneshot::channel();
        self.tx
            .send(Box::new((addr, req, r)))
            .await
            .map_err(|_| ExchangeError::Stopped)?;
        match rx.await.map_err(|_| ExchangeError::Stopped)?? {
            Response::Failure(e) => Err(e.into()),
            r => Ok(r),
        }
    }
}

fn peer_of(addr: &Multiaddr) -> Option<PeerId> {
    match addr.iter().last() {
        Some(Protocol::P2p(p)) => Some(p),
        _ => None,
    }
}

async fn run(
    mut swarm: Swarm<Behaviour>,
    mut rx: mpsc::Receiver<Box<(Multiaddr, Request, Reply)>>,
) {
    let mut waiting: HashMap<PeerId, Vec<(Vec<u8>, Reply)>> = HashMap::new();
    let mut inflight: HashMap<OutboundRequestId, Reply> = HashMap::new();
    loop {
        tokio::select! {
            cmd = rx.recv() => {
                let Some(b) = cmd else { return };
                let (addr, req, reply) = *b;
                let Some(peer) = peer_of(&addr) else {
                    let _ = reply.send(Err(ExchangeError::NoPeerId));
                    continue;
                };
                let bytes = encode_request(&req);
                if bytes.len() > MAX_MESSAGE_BYTES {
                    let _ = reply.send(Err(Refusal::TooLarge.into()));
                    continue;
                }
                if swarm.is_connected(&peer) {
                    let id = swarm.behaviour_mut().send_request(&peer, Frame::Data(bytes));
                    inflight.insert(id, reply);
                } else {
                    let first = !waiting.contains_key(&peer);
                    waiting.entry(peer).or_default().push((bytes, reply));
                    if first {
                        if let Err(e) = swarm.dial(addr) {
                            for (_, r) in waiting.remove(&peer).unwrap_or_default() {
                                let _ = r.send(Err(ExchangeError::Network(e.to_string())));
                            }
                        }
                    }
                }
            },
            event = swarm.select_next_some() => match event {
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    for (bytes, r) in waiting.remove(&peer_id).unwrap_or_default() {
                        let id = swarm.behaviour_mut().send_request(&peer_id, Frame::Data(bytes));
                        inflight.insert(id, r);
                    }
                }
                SwarmEvent::OutgoingConnectionError { peer_id: Some(p), error, .. } => {
                    for (_, r) in waiting.remove(&p).unwrap_or_default() {
                        let _ = r.send(Err(ExchangeError::Network(error.to_string())));
                    }
                }
                SwarmEvent::Behaviour(request_response::Event::Message {
                    message: request_response::Message::Response { request_id, response },
                    ..
                }) => {
                    if let Some(r) = inflight.remove(&request_id) {
                        let _ = r.send(match response {
                            Frame::TooLarge => Err(Refusal::TooLarge.into()),
                            Frame::Data(d) => decode_response(&d).map_err(Into::into),
                        });
                    }
                }
                SwarmEvent::Behaviour(request_response::Event::OutboundFailure { request_id, error, .. }) => {
                    if let Some(r) = inflight.remove(&request_id) {
                        let _ = r.send(Err(ExchangeError::Network(error.to_string())));
                    }
                }
                _ => {}
            }
        }
    }
}

// --------------------------------------------------------- session Nœud

/// Session authentifiée Connecteur → Nœud (`UserCredential`).
#[derive(Clone)]
pub struct NodeSession {
    client: BlockClient,
    node_addr: Multiaddr,
    credential: Credential,
}

impl NodeSession {
    /// `node_addr` suffixée de `/p2p/<PeerId>` ; `pub_node` et `salt` de
    /// l'attachement (`crypto.k-attach`).
    pub fn new(
        client: BlockClient,
        node_addr: Multiaddr,
        priv_user: &[u8; 32],
        pub_user: &[u8; 32],
        pub_node: &[u8; 32],
        salt: &[u8],
    ) -> Result<Self, ExchangeError> {
        let node_peer = peer_of(&node_addr).ok_or(ExchangeError::NoPeerId)?;
        let k = derive_k_attach_as_user(priv_user, pub_node, salt)?;
        let proof = connector_proof(&k, &client.peer_id().to_bytes(), &node_peer.to_bytes());
        Ok(Self {
            client,
            node_addr,
            credential: Credential::User {
                user_id: pub_user.to_vec(),
                proof: proof.to_vec(),
            },
        })
    }

    async fn call(&self, body: Body) -> Result<Response, ExchangeError> {
        let req = Request {
            credential: Some(self.credential.clone()),
            body,
        };
        self.client.request(self.node_addr.clone(), req).await
    }

    pub async fn get_block(&self, hash: &BlockHash) -> Result<Vec<u8>, ExchangeError> {
        match self
            .call(Body::GetBlock {
                hash: hash.to_vec(),
            })
            .await?
        {
            Response::BlockData(d) => Ok(d),
            _ => Err(ExchangeError::Unexpected),
        }
    }

    /// Rend le hash calculé par le Nœud.
    pub async fn put_block(&self, data: Vec<u8>) -> Result<Vec<u8>, ExchangeError> {
        match self.call(Body::PutBlock { data }).await? {
            Response::Stored(h) => Ok(h),
            _ => Err(ExchangeError::Unexpected),
        }
    }

    /// `Ok((committed, current_root))`.
    pub async fn commit_root(
        &self,
        base: &BlockHash,
        new: &BlockHash,
    ) -> Result<(bool, Vec<u8>), ExchangeError> {
        let body = Body::CommitRoot {
            base_root: base.to_vec(),
            new_root: new.to_vec(),
        };
        match self.call(body).await? {
            Response::RootState {
                committed,
                current_root,
            } => Ok((committed, current_root)),
            _ => Err(ExchangeError::Unexpected),
        }
    }

    pub async fn report_incident(&self, hash: &BlockHash) -> Result<(), ExchangeError> {
        match self
            .call(Body::ReportIncident {
                hash: hash.to_vec(),
            })
            .await?
        {
            Response::Ack { .. } => Ok(()),
            _ => Err(ExchangeError::Unexpected),
        }
    }

    pub async fn renew_grant(&self, grant_pub: &Id) -> Result<SignedGrant, ExchangeError> {
        let body = Body::RenewGrant {
            grant_pub: grant_pub.to_vec(),
        };
        match self.call(body).await? {
            Response::GrantIssued(g) => Ok(g),
            _ => Err(ExchangeError::Unexpected),
        }
    }

    /// Remet une délégation au (nouveau) Nœud de cette session.
    pub async fn delegate(&self, d: Delegation) -> Result<(), ExchangeError> {
        match self.call(Body::Delegate(d)).await? {
            Response::Ack { .. } => Ok(()),
            _ => Err(ExchangeError::Unexpected),
        }
    }
}

// ------------------------------------------------ autorisation de secours

/// Clé anonyme de l'appareil et autorisation de secours courante.
pub struct GrantKeeper {
    grant_priv: [u8; 32],
    pub grant: Option<SignedGrant>,
}

impl GrantKeeper {
    /// `grant_priv` : 32 o aléatoires propres à l'appareil, jamais dérivés
    /// de l'identité User.
    pub fn new(grant_priv: [u8; 32]) -> Self {
        Self {
            grant_priv,
            grant: None,
        }
    }

    pub fn grant_pub(&self) -> Id {
        ed25519_dalek::SigningKey::from_bytes(&self.grant_priv)
            .verifying_key()
            .to_bytes()
    }

    /// À renouveler s'il reste moins de la moitié de la durée de validité.
    pub fn needs_renewal(&self, now: u64) -> bool {
        match self.grant.as_ref().and_then(|g| open_grant(g, now).ok()) {
            None => true,
            Some(g) => g.expires_at.saturating_sub(now) < GRANT_TTL_SECONDS / 2,
        }
    }

    /// Renouvelle auprès du Nœud si nécessaire.
    pub async fn refresh(&mut self, node: &NodeSession, now: u64) -> Result<(), ExchangeError> {
        if self.needs_renewal(now) {
            self.grant = Some(node.renew_grant(&self.grant_pub()).await?);
        }
        Ok(())
    }

    /// Lecture de secours d'un fragment chez un partenaire (Nœud injoignable).
    pub async fn fetch_fragment(
        &self,
        client: &BlockClient,
        partner_addr: Multiaddr,
        hash: &BlockHash,
    ) -> Result<Vec<u8>, ExchangeError> {
        let grant = self.grant.clone().ok_or(Refusal::Unauthorized)?;
        let partner = peer_of(&partner_addr).ok_or(ExchangeError::NoPeerId)?;
        let proof = rescue_session_proof(
            &self.grant_priv,
            &client.peer_id().to_bytes(),
            &partner.to_bytes(),
        );
        let req = Request {
            credential: Some(Credential::Rescue { grant, proof }),
            body: Body::FetchFragment {
                hash: hash.to_vec(),
            },
        };
        match client.request(partner_addr, req).await? {
            Response::BlockData(d) => Ok(d),
            _ => Err(ExchangeError::Unexpected),
        }
    }

    /// Délégation au nouveau Nœud `new_node_id` (perte de l'ancien).
    pub fn delegate_to(&self, new_node_id: &Id, expires_at: u64) -> Result<Delegation, Refusal> {
        let grant = self.grant.clone().ok_or(Refusal::Unauthorized)?;
        Ok(delegate(&self.grant_priv, grant, new_node_id, expires_at))
    }
}

// ------------------------------------------- branchements synchrones

fn block_on<F: std::future::Future>(rt: &tokio::runtime::Handle, f: F) -> F::Output {
    if tokio::runtime::Handle::try_current().is_ok() {
        tokio::task::block_in_place(|| rt.block_on(f))
    } else {
        rt.block_on(f)
    }
}

/// Reconstruction depuis la parité (indexée par l'appelant, qui connaît la
/// stripe et ses partenaires).
pub type Reconstructor = Box<dyn Fn(&BlockHash) -> Option<Vec<u8>> + Send + Sync>;

/// `BlockSource` réseau : chemin normal = `GetBlock` au Nœud.
pub struct NetBlockSource {
    pub session: NodeSession,
    pub runtime: tokio::runtime::Handle,
    pub reconstructor: Reconstructor,
}

impl BlockSource for NetBlockSource {
    fn fetch_from_node(&self, hash: &BlockHash) -> Option<Vec<u8>> {
        block_on(&self.runtime, self.session.get_block(hash)).ok()
    }

    fn reconstruct(&self, hash: &BlockHash) -> Option<Vec<u8>> {
        (self.reconstructor)(hash)
    }
}

/// Lecture locale d'un bloc chiffré en attente d'envoi.
pub type BlockLoader = Box<dyn Fn(&BlockHash) -> Option<Vec<u8>> + Send>;
/// Application locale d'une entrée : `(racine de base, nouvelle racine)`.
pub type RootBuilder = Box<dyn FnMut(&Queued) -> Option<(BlockHash, BlockHash)> + Send>;

/// `ReplaySink` réseau : `WriteBlock` → `PutBlock` (hash vérifié) ;
/// `UpdateEntry` / `DeleteEntry` → nouvelle racine construite localement
/// puis `CommitRoot` (refus = conflit).
pub struct NetReplaySink {
    pub session: NodeSession,
    pub runtime: tokio::runtime::Handle,
    pub load_block: BlockLoader,
    pub build_root: RootBuilder,
}

impl ReplaySink for NetReplaySink {
    fn apply(&mut self, m: &Queued) -> bool {
        match &m.op {
            Op::WriteBlock { block_hash } => {
                let Some(data) = (self.load_block)(block_hash) else {
                    return false;
                };
                block_on(&self.runtime, self.session.put_block(data))
                    .is_ok_and(|h| h == block_hash.to_vec())
            }
            Op::UpdateEntry { .. } | Op::DeleteEntry { .. } => {
                let Some((base, new)) = (self.build_root)(m) else {
                    return false;
                };
                block_on(&self.runtime, self.session.commit_root(&base, &new))
                    .is_ok_and(|(committed, _)| committed)
            }
        }
    }
}
