//! Client du canal d'administration du Nœud — id `deploiement.appairage-admin`.
//! Réf. spec : docs/07-deploiement/appairage-admin.md. Paire libp2p jetable
//! (les clés d'Utilisateur ne servent jamais ici) ; appairage SPAKE2 d'un
//! Nœud sous identité temporaire, ou connexion TOTP au `PeerId` connu.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{self, OutboundRequestId, ProtocolSupport};
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::SwarmEvent;
use libp2p::{identity, noise, tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm};
use s3m_protocol::admin::{
    confirm_mac, pake_finish, pake_start, AdminRequest, AdminResponse, Side, PROTOCOL,
};
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};

type Reply = oneshot::Sender<Result<AdminResponse, String>>;
type Rr = request_response::json::Behaviour<AdminRequest, AdminResponse>;

/// Client (une paire libp2p par client : les sessions y sont liées).
#[derive(Clone)]
pub struct AdminClient {
    peer_id: PeerId,
    tx: mpsc::Sender<(Multiaddr, AdminRequest, Reply)>,
}

fn peer_of(addr: &Multiaddr) -> Option<PeerId> {
    match addr.iter().last() {
        Some(Protocol::P2p(p)) => Some(p),
        _ => None,
    }
}

impl AdminClient {
    pub fn start() -> Result<Self, String> {
        let key = identity::Keypair::generate_ed25519();
        let peer_id = key.public().to_peer_id();
        let swarm = libp2p::SwarmBuilder::with_existing_identity(key)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| e.to_string())?
            .with_behaviour(|_| {
                Rr::new(
                    [(StreamProtocol::new(PROTOCOL), ProtocolSupport::Outbound)],
                    request_response::Config::default()
                        .with_request_timeout(Duration::from_secs(20)),
                )
            })
            .unwrap_or_else(|e| match e {})
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(120)))
            .build();
        let (tx, rx) = mpsc::channel(32);
        tokio::spawn(run(swarm, rx));
        Ok(Self { peer_id, tx })
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Requête vers `addr` (suffixée de `/p2p/<PeerId>`).
    pub async fn request(
        &self,
        addr: &Multiaddr,
        req: AdminRequest,
    ) -> Result<AdminResponse, String> {
        let (r, rx) = oneshot::channel();
        self.tx
            .send((addr.clone(), req, r))
            .await
            .map_err(|_| "client arrêté".to_string())?;
        match rx.await.map_err(|_| "client arrêté".to_string())?? {
            AdminResponse::Error(e) => Err(e),
            r => Ok(r),
        }
    }

    /// Mode annoncé par le Nœud (`setup` ou `node`).
    pub async fn hello(&self, addr: &Multiaddr) -> Result<String, String> {
        match self.request(addr, AdminRequest::Hello {}).await? {
            AdminResponse::Hello { mode, .. } => Ok(mode),
            _ => Err("réponse inattendue".into()),
        }
    }

    /// Appairage d'un Nœud sous identité temporaire avec son code.
    pub async fn pair(&self, addr: &Multiaddr, code: &str) -> Result<RemoteSession, String> {
        let node = peer_of(addr).ok_or("adresse sans /p2p/<identifiant>")?;
        let (state, msg) = pake_start(code);
        let AdminResponse::PakeReply { msg: reply } = self
            .request(
                addr,
                AdminRequest::PakeStart {
                    msg: hex::encode(msg),
                },
            )
            .await?
        else {
            return Err("réponse inattendue".into());
        };
        let k = pake_finish(state, &hex::decode(reply).map_err(|e| e.to_string())?)?;
        let (np, cp) = (node.to_bytes(), self.peer_id.to_bytes());
        let mac = confirm_mac(&k, Side::Client, &np, &cp);
        let AdminResponse::Session {
            token,
            mac: Some(node_mac),
        } = self
            .request(
                addr,
                AdminRequest::PakeConfirm {
                    mac: hex::encode(mac),
                },
            )
            .await
            .map_err(|_| "code d'appairage refusé".to_string())?
        else {
            return Err("réponse inattendue".into());
        };
        // Le Nœud prouve à son tour qu'il connaît le code.
        if hex::decode(node_mac).ok().as_deref() != Some(&confirm_mac(&k, Side::Node, &np, &cp)[..])
        {
            return Err("ce Nœud ne connaît pas le code : appairage abandonné".into());
        }
        Ok(RemoteSession {
            client: self.clone(),
            addr: addr.clone(),
            token,
        })
    }

    /// Connexion à un Nœud configuré avec le code 2FA.
    pub async fn login(&self, addr: &Multiaddr, totp: &str) -> Result<RemoteSession, String> {
        match self
            .request(
                addr,
                AdminRequest::Login {
                    totp: totp.trim().into(),
                },
            )
            .await?
        {
            AdminResponse::Session { token, .. } => Ok(RemoteSession {
                client: self.clone(),
                addr: addr.clone(),
                token,
            }),
            _ => Err("réponse inattendue".into()),
        }
    }
}

/// Session ouverte sur un Nœud.
#[derive(Clone)]
pub struct RemoteSession {
    client: AdminClient,
    pub addr: Multiaddr,
    token: String,
}

impl RemoteSession {
    async fn call(&self, op: &str, name: Option<&str>, body: Value) -> Result<Value, String> {
        let req = AdminRequest::Call {
            token: self.token.clone(),
            op: op.into(),
            name: name.map(Into::into),
            body,
        };
        match self.client.request(&self.addr, req).await? {
            AdminResponse::Result(v) => Ok(v),
            _ => Err("réponse inattendue".into()),
        }
    }

    pub async fn status(&self) -> Result<Value, String> {
        self.call("status", None, Value::Null).await
    }

    /// Points de la carte du monde du Nœud.
    pub async fn map(&self) -> Result<Value, String> {
        self.call("map", None, Value::Null).await
    }

    pub async fn action(&self, name: &str, body: Value) -> Result<Value, String> {
        self.call("action", Some(name), body).await
    }
}

async fn run(mut swarm: Swarm<Rr>, mut rx: mpsc::Receiver<(Multiaddr, AdminRequest, Reply)>) {
    let mut waiting: HashMap<PeerId, Vec<(AdminRequest, Reply)>> = HashMap::new();
    let mut inflight: HashMap<OutboundRequestId, Reply> = HashMap::new();
    loop {
        tokio::select! {
            cmd = rx.recv() => {
                let Some((addr, req, reply)) = cmd else { return };
                let Some(peer) = peer_of(&addr) else {
                    let _ = reply.send(Err("adresse sans /p2p/<identifiant>".into()));
                    continue;
                };
                if swarm.is_connected(&peer) {
                    inflight.insert(swarm.behaviour_mut().send_request(&peer, req), reply);
                } else {
                    let first = !waiting.contains_key(&peer);
                    waiting.entry(peer).or_default().push((req, reply));
                    if first {
                        let opts = DialOpts::unknown_peer_id().address(addr).allocate_new_port().build();
                        if let Err(e) = swarm.dial(opts) {
                            for (_, r) in waiting.remove(&peer).unwrap_or_default() {
                                let _ = r.send(Err(e.to_string()));
                            }
                        }
                    }
                }
            },
            event = swarm.select_next_some() => match event {
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    for (req, r) in waiting.remove(&peer_id).unwrap_or_default() {
                        inflight.insert(swarm.behaviour_mut().send_request(&peer_id, req), r);
                    }
                }
                SwarmEvent::OutgoingConnectionError { error, .. } => {
                    // Le pair n'est pas toujours connu (numérotation sans PeerId) :
                    // toutes les attentes sans connexion échouent.
                    let stale: Vec<PeerId> = waiting.keys().filter(|p| !swarm.is_connected(p)).copied().collect();
                    for p in stale {
                        for (_, r) in waiting.remove(&p).unwrap_or_default() {
                            let _ = r.send(Err(format!("Nœud injoignable : {error}")));
                        }
                    }
                }
                SwarmEvent::Behaviour(request_response::Event::Message {
                    message: request_response::Message::Response { request_id, response },
                    ..
                }) => {
                    if let Some(r) = inflight.remove(&request_id) {
                        let _ = r.send(Ok(response));
                    }
                }
                SwarmEvent::Behaviour(request_response::Event::OutboundFailure { request_id, error, .. }) => {
                    if let Some(r) = inflight.remove(&request_id) {
                        let _ = r.send(Err(error.to_string()));
                    }
                }
                _ => {}
            }
        }
    }
}

/// Adresse d'administration par défaut d'un Nœud connu par son adresse
/// d'échange de blocs : même IP, port d'administration, même `PeerId`.
pub fn default_admin_addr(blocks_addr: &str) -> Result<Multiaddr, String> {
    let m: Multiaddr = blocks_addr.parse().map_err(|e| format!("adresse : {e}"))?;
    let peer = peer_of(&m).ok_or("adresse sans /p2p/<identifiant>")?;
    let ip = m
        .iter()
        .find_map(|p| match p {
            Protocol::Ip4(_) | Protocol::Ip6(_) | Protocol::Dns(_) | Protocol::Dns4(_) => Some(p),
            _ => None,
        })
        .ok_or("adresse sans IP")?;
    Ok(Multiaddr::empty()
        .with(ip)
        .with(Protocol::Tcp(s3m_protocol::admin::DEFAULT_PORT))
        .with(Protocol::P2p(peer)))
}

/// Partage d'une session entre le dashboard distant et ses tâches.
pub type SharedSession = Arc<RemoteSession>;
