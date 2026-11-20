//! Protocole d'échange de blocs — id `protocols.echange-blocs`, partie
//! `node` : service (règles, état) et transport libp2p requête/réponse.
//! Réf. spec : docs/04-protocols/echange-blocs.md.
//!
//! - [`NodeService`] : traitement d'une requête, sans I/O. Côté Connecteur
//!   (blocs, racine, incidents, autorisations, délégations) et côté
//!   partenaire (dépôt de fragments avec reçu signé, challenges PoS,
//!   récupération, avis de suppression, lecture de secours).
//! - [`BlockServer`] : écoute `/p2p-storage/blocks/1` et émet des requêtes
//!   vers d'autres Nœuds (identité libp2p dérivée de `priv_node`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{self, OutboundRequestId, ProtocolSupport};
use libp2p::swarm::SwarmEvent;
use libp2p::{identity, noise, tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm};
use p2p_storage_core::k_attach::derive_k_attach_as_node;
use p2p_storage_core::symmetric_suite::hash_sha256;
use p2p_storage_protocol::dht::verify_migration_pointer;
use p2p_storage_protocol::exchange::*;
use p2p_storage_protocol::fb::dht as fbd;
use tokio::sync::{mpsc, oneshot};

use crate::chunk_store::{ChunkStore, MemoryStore, Space, StoreError};
use crate::pos::challenge_response;
use crate::tombstones::{apply_received, PartnerLedger, TombstoneError, TombstoneNotice};

/// Utilisateur rattaché (`node.AttachedUser`), vu du service d'échange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAccount {
    pub salt: Vec<u8>,
    pub quota_bytes: u64,
    pub used_bytes: u64,
    /// Racine courante du système de fichiers (`[0; 32]` : vide).
    pub root: Id,
}

/// Partenaire de troc (`node.PartnerAccount`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PartnerState {
    /// Nombre maximal de fragments hébergés pour lui (solde de troc).
    pub allowance: u64,
    pub ledger: PartnerLedger,
    /// Dernier échange (secondes Unix).
    pub last_seen: u64,
}

/// État et règles du service d'échange d'un Nœud.
pub struct NodeService {
    priv_node: [u8; 32],
    node_id: Id,
    /// Anciens `node_id` couverts par les autorisations émises (migration).
    pub previous_node_ids: Vec<Id>,
    pub users: HashMap<Id, UserAccount>,
    /// Blocs de données des Utilisateurs et fragments des partenaires.
    pub store: Box<dyn ChunkStore>,
    pub partners: HashMap<Id, PartnerState>,
    /// Pointeurs de migration valides lus dans la DHT : ancien → nouveau.
    pub successors: HashMap<Id, Id>,
    pub incidents: Vec<Id>,
    /// Délégations reçues (lecture chez les partenaires de l'ancien Nœud).
    pub delegations: Vec<Delegation>,
    /// Blocs reçus à disperser : `(pub_user, hash)` (moteur de dispersion).
    pub dispersal_queue: Vec<(Id, Id)>,
    /// Après restauration, la racine courante de ces Utilisateurs est
    /// inconnue : leur prochaine validation est adoptée telle quelle.
    pub adopt_next_root: std::collections::HashSet<Id>,
    limiter: RescueLimiter,
}

fn store_refusal(e: StoreError) -> Refusal {
    match e {
        StoreError::BadSize => Refusal::Malformed,
        StoreError::Conflict => Refusal::Unauthorized,
        StoreError::Storage(_) => Refusal::QuotaExceeded,
    }
}

fn id32(v: &[u8]) -> Result<Id, Refusal> {
    v.try_into().map_err(|_| Refusal::Malformed)
}

impl NodeService {
    /// Service en mémoire (tests).
    pub fn new(priv_node: [u8; 32]) -> Self {
        Self::with_store(priv_node, Box::<MemoryStore>::default())
    }

    pub fn with_store(priv_node: [u8; 32], store: Box<dyn ChunkStore>) -> Self {
        let node_id = ed25519_dalek::SigningKey::from_bytes(&priv_node)
            .verifying_key()
            .to_bytes();
        Self {
            priv_node,
            node_id,
            previous_node_ids: Vec::new(),
            users: HashMap::new(),
            store,
            partners: HashMap::new(),
            successors: HashMap::new(),
            incidents: Vec::new(),
            delegations: Vec::new(),
            dispersal_queue: Vec::new(),
            adopt_next_root: Default::default(),
            limiter: RescueLimiter::default(),
        }
    }

    pub fn node_id(&self) -> Id {
        self.node_id
    }

    /// Graine `priv_node` (signatures du moteur de dispersion).
    pub fn priv_node(&self) -> [u8; 32] {
        self.priv_node
    }

    /// Traite une requête. `from` / `local` : octets des `PeerId` de la
    /// connexion ; `from_node` : `pub_node` du demandeur s'il est un Nœud.
    pub fn handle(
        &mut self,
        from: &[u8],
        from_node: Option<Id>,
        local: &[u8],
        req: Request,
        now: u64,
    ) -> Response {
        self.dispatch(from, from_node, local, req, now)
            .unwrap_or_else(Response::Failure)
    }

    fn user(&self, cred: Option<&Credential>, from: &[u8], local: &[u8]) -> Result<Id, Refusal> {
        let Some(Credential::User { user_id, proof }) = cred else {
            return Err(Refusal::Unauthorized);
        };
        let pub_user = id32(user_id)?;
        let acc = self.users.get(&pub_user).ok_or(Refusal::Unauthorized)?;
        let k = derive_k_attach_as_node(&self.priv_node, &pub_user, &acc.salt)
            .map_err(|_| Refusal::Unauthorized)?;
        if !verify_connector_proof(&k, from, local, proof) {
            return Err(Refusal::Unauthorized);
        }
        Ok(pub_user)
    }

    fn partner(&mut self, from_node: Option<Id>, now: u64) -> Result<Id, Refusal> {
        let p = from_node.ok_or(Refusal::Unauthorized)?;
        let st = self.partners.get_mut(&p).ok_or(Refusal::Unauthorized)?;
        st.last_seen = now;
        Ok(p)
    }

    fn dispatch(
        &mut self,
        from: &[u8],
        from_node: Option<Id>,
        local: &[u8],
        req: Request,
        now: u64,
    ) -> Result<Response, Refusal> {
        let cred = req.credential.as_ref();
        match req.body {
            Body::GetBlock { hash } => {
                let u = self.user(cred, from, local)?;
                match self.store.get(Space::UserBlock, &id32(&hash)?) {
                    Some((o, d)) if o == u => Ok(Response::BlockData(d)),
                    _ => Err(Refusal::NotFound),
                }
            }
            Body::PutBlock { data } => {
                let u = self.user(cred, from, local)?;
                let hash = hash_sha256(&data);
                if !self.store.contains(&hash) {
                    let acc = self.users.get(&u).ok_or(Refusal::Unauthorized)?;
                    let used = acc.used_bytes + data.len() as u64;
                    if used > acc.quota_bytes {
                        return Err(Refusal::QuotaExceeded);
                    }
                    self.store
                        .put(Space::UserBlock, &u, &hash, &data)
                        .map_err(store_refusal)?;
                    if let Some(acc) = self.users.get_mut(&u) {
                        acc.used_bytes = used;
                    }
                    self.dispersal_queue.push((u, hash));
                } else if self.store.get(Space::UserBlock, &hash).map(|(o, _)| o) != Some(u) {
                    return Err(Refusal::Unauthorized);
                }
                Ok(Response::Stored(hash.to_vec()))
            }
            Body::CommitRoot {
                base_root,
                new_root,
            } => {
                let u = self.user(cred, from, local)?;
                let (base, new) = (id32(&base_root)?, id32(&new_root)?);
                let adopt = self.adopt_next_root.remove(&u);
                let acc = self.users.get_mut(&u).ok_or(Refusal::Unauthorized)?;
                let committed = adopt || acc.root == base;
                if committed {
                    acc.root = new;
                }
                Ok(Response::RootState {
                    committed,
                    current_root: acc.root.to_vec(),
                })
            }
            Body::ReportIncident { hash } => {
                self.user(cred, from, local)?;
                self.incidents.push(id32(&hash)?);
                Ok(Response::Ack { freed: 0 })
            }
            Body::RenewGrant { grant_pub } => {
                self.user(cred, from, local)?;
                Ok(Response::GrantIssued(issue_grant(
                    &self.priv_node,
                    &id32(&grant_pub)?,
                    now,
                    &self.previous_node_ids,
                )))
            }
            Body::Delegate(d) => {
                self.user(cred, from, local)?;
                open_delegation(&d, now)?;
                if d.delegate_node_id != self.node_id {
                    return Err(Refusal::Unauthorized);
                }
                self.delegations.push(d);
                Ok(Response::Ack { freed: 0 })
            }
            Body::StoreFragment { data } => {
                let p = self.partner(from_node, now)?;
                let hash = hash_sha256(&data);
                if !self.store.contains(&hash) {
                    let st = self.partners.get(&p).ok_or(Refusal::Unauthorized)?;
                    if st.ledger.hosted_by_partner >= st.allowance {
                        return Err(Refusal::QuotaExceeded);
                    }
                    self.store
                        .put(Space::Fragment, &p, &hash, &data)
                        .map_err(store_refusal)?;
                    if let Some(st) = self.partners.get_mut(&p) {
                        st.ledger.hosted_by_partner += 1;
                    }
                } else if self.store.get(Space::Fragment, &hash).map(|(o, _)| o) != Some(p) {
                    return Err(Refusal::Unauthorized);
                }
                Ok(Response::FragmentReceipt {
                    hash: hash.to_vec(),
                    signature: sign_receipt(&self.priv_node, &hash, &p),
                })
            }
            Body::Challenge { hash, nonce } => {
                let p = self.partner(from_node, now)?;
                let f = self.owned_fragment(&hash, &p)?;
                let nonce: [u8; 32] = nonce.try_into().map_err(|_| Refusal::Malformed)?;
                Ok(Response::ChallengeResponse(
                    challenge_response(&f, &nonce).to_vec(),
                ))
            }
            Body::FetchFragment { hash } => {
                if cred.is_none() {
                    let p = self.partner(from_node, now)?;
                    return Ok(Response::BlockData(self.owned_fragment(&hash, &p)?));
                }
                // Secours : identifiant contrôlé avant tout accès disque.
                let grant = authorize_rescue(cred, from, from_node.as_ref(), local, now)?;
                if !self.limiter.allow(&grant.grant_pub, now) {
                    return Err(Refusal::RateLimited);
                }
                let (owner, data) = self
                    .store
                    .get(Space::Fragment, &id32(&hash)?)
                    .ok_or(Refusal::NotFound)?;
                let successors = &self.successors;
                if !covers(&grant, &owner, &|o| successors.get(o).copied()) {
                    return Err(Refusal::Unauthorized);
                }
                Ok(Response::BlockData(data))
            }
            Body::Tombstone {
                timestamp,
                hashes,
                signature,
            } => {
                let p = self.partner(from_node, now)?;
                if !hashes.len().is_multiple_of(32) {
                    return Err(Refusal::Malformed);
                }
                let notice = TombstoneNotice {
                    timestamp,
                    block_hashes: hashes.chunks(32).map(|c| c.try_into().unwrap()).collect(),
                    signature: signature.try_into().map_err(|_| Refusal::Malformed)?,
                };
                let store = &mut self.store;
                let st = self.partners.get_mut(&p).ok_or(Refusal::Unauthorized)?;
                let freed = apply_received(&mut st.ledger, &p, &notice, &mut |h| {
                    store.remove(Space::Fragment, &p, h)
                })
                .map_err(|e| match e {
                    TombstoneError::Replay => Refusal::Replayed,
                    TombstoneError::Signature(_) => Refusal::Unauthorized,
                })?;
                Ok(Response::Ack { freed })
            }
        }
    }

    fn owned_fragment(&self, hash: &[u8], owner: &Id) -> Result<Vec<u8>, Refusal> {
        match self.store.get(Space::Fragment, &id32(hash)?) {
            Some((o, d)) if o == *owner => Ok(d),
            _ => Err(Refusal::NotFound),
        }
    }

    /// Purge les fragments des Nœuds silencieux depuis au moins
    /// `SILENT_NODE_RETENTION_SECONDS` ; rend le nombre de Nœuds purgés.
    pub fn purge_silent_partners(&mut self, now: u64) -> usize {
        let silent: Vec<Id> = self
            .partners
            .iter()
            .filter(|(_, s)| s.last_seen + SILENT_NODE_RETENTION_SECONDS <= now)
            .map(|(id, _)| *id)
            .collect();
        let owners = self.store.owners(Space::Fragment);
        let mut purged = 0;
        for p in silent.iter().filter(|p| owners.contains(p)) {
            self.store.remove_owner(Space::Fragment, p);
            if let Some(st) = self.partners.get_mut(p) {
                st.ledger.hosted_by_partner = 0;
            }
            purged += 1;
        }
        purged
    }
}

/// Successeur annoncé par l'entrée DHT Node (enveloppe déjà validée par
/// l'adaptateur DHT) de `node_id`, si son `migration_pointer` est valide.
pub fn successor_from_node_entry(envelope: &[u8], node_id: &Id) -> Option<Id> {
    let env = flatbuffers::root::<fbd::DhtEnvelope>(envelope).ok()?;
    let e = fbd::root_as_node_entry(env.payload()?.bytes()).ok()?;
    let p = e.migration_pointer()?;
    let rec = e.pub_node_recovery()?;
    verify_migration_pointer(p, rec.bytes(), node_id, None)
        .ok()?
        .try_into()
        .ok()
}

/// Rafraîchit [`NodeService::successors`] depuis la DHT pour tous les Nœuds
/// propriétaires de fragments hébergés.
pub async fn refresh_successors(
    service: &Mutex<NodeService>,
    dht: &crate::dht_directory::DhtNode,
) -> Result<(), crate::dht_directory::DhtNodeError> {
    let owners: Vec<Id> = {
        let s = service.lock().unwrap();
        s.store.owners(Space::Fragment)
    };
    for owner in owners {
        let next = dht
            .get(owner.to_vec())
            .await?
            .and_then(|env| successor_from_node_entry(&env, &owner));
        let mut s = service.lock().unwrap();
        match next {
            Some(n) => s.successors.insert(owner, n),
            None => s.successors.remove(&owner),
        };
    }
    Ok(())
}

// ---------------------------------------------------------------- transport

/// `pub_node` d'un `PeerId` Ed25519 (Nœud), sinon `None` (Connecteur
/// éphémère compris : il n'est pas partenaire).
pub fn node_id_of(peer: &PeerId) -> Option<Id> {
    let mh = peer.as_ref();
    if mh.code() != 0 {
        return None;
    }
    identity::PublicKey::try_decode_protobuf(mh.digest())
        .ok()?
        .try_into_ed25519()
        .ok()
        .map(|k| k.to_bytes())
}

/// Trame préfixée `u32be` ; au-delà de `MAX_MESSAGE_BYTES`, le corps n'est
/// pas lu.
#[derive(Debug, Clone)]
pub enum Frame {
    Data(Vec<u8>),
    TooLarge,
}

/// Codec `/p2p-storage/blocks/1`.
#[derive(Debug, Clone, Default)]
pub struct FrameCodec;

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

/// Erreurs de transport.
#[derive(Debug, thiserror::Error)]
pub enum ExchangeError {
    #[error("réseau : {0}")]
    Network(String),
    #[error("adresse sans /p2p/<PeerId>")]
    NoPeerId,
    #[error("réponse refusée : {0}")]
    Refused(#[from] Refusal),
    #[error("service arrêté")]
    Stopped,
}

type Reply = oneshot::Sender<Result<Response, ExchangeError>>;

enum Cmd {
    ListenAddr(oneshot::Sender<Option<Multiaddr>>),
    Request(Box<(Multiaddr, Request, Reply)>),
}

type Behaviour = request_response::Behaviour<FrameCodec>;

/// Construit un swarm d'échange de blocs (partagé avec le Connecteur par
/// copie de ce motif : identité fournie, TCP + Noise + Yamux).
fn build_swarm(keypair: identity::Keypair) -> Result<Swarm<Behaviour>, ExchangeError> {
    let net = |e: &dyn std::fmt::Display| ExchangeError::Network(e.to_string());
    Ok(libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| net(&e))?
        .with_behaviour(|_| {
            request_response::Behaviour::new(
                [(StreamProtocol::new(PROTOCOL), ProtocolSupport::Full)],
                request_response::Config::default().with_request_timeout(Duration::from_secs(30)),
            )
        })
        .map_err(|e| net(&e))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build())
}

/// Serveur d'échange de blocs d'un Nœud (et client vers ses partenaires).
pub struct BlockServer {
    peer_id: PeerId,
    tx: mpsc::Sender<Cmd>,
}

impl BlockServer {
    /// Démarre l'écoute sur `listen` avec l'identité `priv_node` du service.
    pub async fn start(
        node_seed: [u8; 32],
        listen: Multiaddr,
        service: Arc<Mutex<NodeService>>,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Result<Self, ExchangeError> {
        let net = |e: &dyn std::fmt::Display| ExchangeError::Network(e.to_string());
        let secret =
            identity::ed25519::SecretKey::try_from_bytes(node_seed).map_err(|e| net(&e))?;
        let keypair = identity::Keypair::from(identity::ed25519::Keypair::from(secret));
        let peer_id = keypair.public().to_peer_id();
        let mut swarm = build_swarm(keypair)?;
        swarm.listen_on(listen).map_err(|e| net(&e))?;
        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(run(swarm, rx, Some(service), clock));
        Ok(Self { peer_id, tx })
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Première adresse d'écoute, suffixée de `/p2p/<PeerId>`.
    pub async fn listen_addr(&self) -> Option<Multiaddr> {
        listen_addr(&self.tx, self.peer_id).await
    }

    /// Envoie une requête à un pair (`addr` suffixée de `/p2p/<PeerId>`).
    pub async fn request(&self, addr: Multiaddr, req: Request) -> Result<Response, ExchangeError> {
        request(&self.tx, addr, req).await
    }
}

async fn listen_addr(tx: &mpsc::Sender<Cmd>, peer_id: PeerId) -> Option<Multiaddr> {
    for _ in 0..50 {
        let (r, rx) = oneshot::channel();
        tx.send(Cmd::ListenAddr(r)).await.ok()?;
        if let Some(a) = rx.await.ok()? {
            return Some(a.with(Protocol::P2p(peer_id)));
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    None
}

async fn request(
    tx: &mpsc::Sender<Cmd>,
    addr: Multiaddr,
    req: Request,
) -> Result<Response, ExchangeError> {
    let (r, rx) = oneshot::channel();
    tx.send(Cmd::Request(Box::new((addr, req, r))))
        .await
        .map_err(|_| ExchangeError::Stopped)?;
    rx.await.map_err(|_| ExchangeError::Stopped)?
}

fn peer_of(addr: &Multiaddr) -> Option<PeerId> {
    match addr.iter().last() {
        Some(Protocol::P2p(p)) => Some(p),
        _ => None,
    }
}

fn decode_frame(f: Frame) -> Result<Response, ExchangeError> {
    match f {
        Frame::TooLarge => Err(Refusal::TooLarge.into()),
        Frame::Data(d) => Ok(decode_response(&d)?),
    }
}

async fn run(
    mut swarm: Swarm<Behaviour>,
    mut rx: mpsc::Receiver<Cmd>,
    service: Option<Arc<Mutex<NodeService>>>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
) {
    let local = *swarm.local_peer_id();
    let mut waiting: HashMap<PeerId, Vec<(Vec<u8>, Reply)>> = HashMap::new();
    let mut inflight: HashMap<OutboundRequestId, Reply> = HashMap::new();
    loop {
        tokio::select! {
            cmd = rx.recv() => match cmd {
                None => return,
                Some(Cmd::ListenAddr(r)) => { let _ = r.send(swarm.listeners().next().cloned()); }
                Some(Cmd::Request(b)) => {
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
                SwarmEvent::Behaviour(request_response::Event::Message { peer, message, .. }) => match message {
                    request_response::Message::Request { request, channel, .. } => {
                        let resp = match (&service, request) {
                            (None, _) => Response::Failure(Refusal::Unauthorized),
                            (Some(_), Frame::TooLarge) => Response::Failure(Refusal::TooLarge),
                            (Some(s), Frame::Data(d)) => match decode_request(&d) {
                                Err(e) => Response::Failure(e),
                                Ok(req) => s.lock().unwrap().handle(
                                    &peer.to_bytes(), node_id_of(&peer), &local.to_bytes(), req, clock(),
                                ),
                            },
                        };
                        let _ = swarm.behaviour_mut().send_response(channel, Frame::Data(encode_response(&resp)));
                    }
                    request_response::Message::Response { request_id, response } => {
                        if let Some(r) = inflight.remove(&request_id) {
                            let _ = r.send(decode_frame(response));
                        }
                    }
                },
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
