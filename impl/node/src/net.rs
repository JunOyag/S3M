//! Pile réseau unique du Nœud et traversée de NAT — id
//! `network.traversee-nat` (partie node). Réf. spec :
//! docs/01-network-dht/traversee-nat.md.
//!
//! Un seul swarm libp2p (identité `pub_node`) porte la DHT, l'échange de
//! blocs et la traversée de NAT : TCP + QUIC, Identify, AutoNAT, UPnP,
//! service de relais (circuit v2, limites prudentes), client de relais et
//! perçage DCUtR. Les poignées `DhtNode` et `BlockServer` habituelles en
//! sont des vues.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use libp2p::kad::store::MemoryStore;
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{
    autonat, dcutr, identify, identity, kad, noise, relay, tcp, upnp, yamux, Multiaddr, PeerId,
    StreamProtocol, Swarm,
};
use p2p_storage_protocol::exchange::PROTOCOL;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::dht_directory::{
    Command as DhtCommand, DhtLoop, DhtNode, SharedVdfVerifier, KAD_PROTOCOL,
};
use crate::exchange::{
    BlockServer, Cmd as BlockCmd, ExchangeLoop, FrameCodec, NodeService, RrHost,
};

/// Protocole Identify du réseau.
pub const IDENTIFY_PROTOCOL: &str = "/p2p-storage/id/1.0.0";
const RELAY_HOP: &str = "/libp2p/circuit/relay/0.2.0/hop";
/// Réservations de relais visées quand le Nœud est derrière un NAT.
pub const TARGET_RELAYS: usize = 2;

/// Limites du service de relais rendu aux Nœuds derrière un NAT.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayLimits {
    pub max_reservations: usize,
    pub max_circuit_duration_s: u64,
    pub max_circuit_bytes: u64,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            max_reservations: 16,
            max_circuit_duration_s: 600,
            max_circuit_bytes: 16 << 20,
        }
    }
}

/// Paramètres réseau.
pub struct NetConfig {
    pub node_seed: [u8; 32],
    /// Adresses d'écoute TCP ; l'équivalent QUIC (même port) est ajouté.
    pub listen: Vec<Multiaddr>,
    pub bootstrap: Vec<Multiaddr>,
    pub vdf: SharedVdfVerifier,
    pub clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    pub service: Arc<Mutex<NodeService>>,
    pub upnp: bool,
    pub relay_server: bool,
    pub relay_limits: RelayLimits,
    /// Relais imposés (`…/p2p/<relais>`), sinon choisis automatiquement.
    pub relays: Vec<Multiaddr>,
    /// Réserver des relais même sans NAT détecté (tests, dépannage).
    pub force_relay: bool,
    /// Adresses externes déclarées (`public_ip` de la configuration).
    pub external: Vec<Multiaddr>,
    /// Tenir les adresses d'écoute pour publiques (tests en boucle locale).
    pub assume_listen_public: bool,
}

/// État de la traversée de NAT (dashboard, entrée Node).
#[derive(Debug, Clone, Default)]
pub struct NatState {
    /// `inconnu`, `public`, `derrière un NAT`.
    pub status: String,
    pub upnp: String,
    /// Adresses externes confirmées (avec `/p2p/<soi>`).
    pub external: Vec<String>,
    /// Adresses via relais (avec `/p2p/<soi>`).
    pub relayed: Vec<String>,
    pub listen: Vec<String>,
    pub hole_punch_ok: u64,
    pub hole_punch_failed: u64,
    pub relay_circuits_served: u64,
    /// Dernière erreur de réservation de relais.
    pub relay_error: Option<String>,
}

impl NatState {
    /// Multiaddrs à publier : directes (TCP puis QUIC), puis via relais.
    pub fn announced(&self) -> Vec<String> {
        let mut direct = self.external.clone();
        direct.sort_by_key(|a| a.contains("/quic"));
        direct.extend(self.relayed.iter().cloned());
        direct.dedup();
        direct
    }

    /// Adresse TCP directe confirmée `(ip, port)`.
    pub fn direct_tcp(&self) -> Option<(String, u16)> {
        self.external.iter().find_map(|a| {
            let m: Multiaddr = a.parse().ok()?;
            let mut ip = None;
            let mut port = None;
            for p in m.iter() {
                match p {
                    Protocol::Ip4(v) => ip = Some(v.to_string()),
                    Protocol::Ip6(v) => ip = Some(v.to_string()),
                    Protocol::Tcp(v) => port = Some(v),
                    Protocol::Udp(_) => return None,
                    _ => {}
                }
            }
            Some((ip?, port?))
        })
    }
}

#[derive(NetworkBehaviour)]
pub(crate) struct NodeBehaviour {
    kad: kad::Behaviour<MemoryStore>,
    rr: request_response::Behaviour<FrameCodec>,
    identify: identify::Behaviour,
    autonat: autonat::Behaviour,
    upnp: Toggle<upnp::tokio::Behaviour>,
    relay_server: Toggle<relay::Behaviour>,
    relay_client: relay::client::Behaviour,
    dcutr: dcutr::Behaviour,
}

impl RrHost for Swarm<NodeBehaviour> {
    fn rr(&mut self) -> &mut request_response::Behaviour<FrameCodec> {
        &mut self.behaviour_mut().rr
    }
    fn connected(&self, peer: &PeerId) -> bool {
        self.is_connected(peer)
    }
    fn dial_addr(&mut self, addr: Multiaddr) -> Result<(), String> {
        self.dial(new_port(addr)).map_err(|e| e.to_string())
    }
    fn listen_addr(&self) -> Option<Multiaddr> {
        first_direct(self)
    }
}

/// Connexion sortante sur un port neuf : Windows refuse la réutilisation du
/// port d'écoute (`SO_REUSEPORT` absent) ; le perçage passe alors par QUIC.
fn new_port(addr: Multiaddr) -> libp2p::swarm::dial_opts::DialOpts {
    libp2p::swarm::dial_opts::DialOpts::unknown_peer_id()
        .address(addr)
        .allocate_new_port()
        .build()
}

fn first_direct(sw: &Swarm<NodeBehaviour>) -> Option<Multiaddr> {
    sw.listeners()
        .find(|a| {
            !a.iter()
                .any(|p| matches!(p, Protocol::P2pCircuit | Protocol::Udp(_)))
        })
        .cloned()
}

fn quic_of(tcp: &Multiaddr) -> Option<Multiaddr> {
    let mut out = Multiaddr::empty();
    let mut seen_tcp = false;
    for p in tcp.iter() {
        match p {
            Protocol::Tcp(port) => {
                out.push(Protocol::Udp(port));
                out.push(Protocol::QuicV1);
                seen_tcp = true;
            }
            other => out.push(other),
        }
    }
    seen_tcp.then_some(out)
}

fn with_self(a: &Multiaddr, me: PeerId) -> String {
    if matches!(a.iter().last(), Some(Protocol::P2p(_))) {
        a.to_string()
    } else {
        a.clone().with(Protocol::P2p(me)).to_string()
    }
}

/// Adresse publiquement routable (hors réseaux privés et boucle locale).
fn is_public(a: &Multiaddr) -> bool {
    a.iter().all(|p| match p {
        Protocol::Ip4(v) => {
            !(v.is_private() || v.is_loopback() || v.is_link_local() || v.is_unspecified())
        }
        Protocol::Ip6(v) => !(v.is_loopback() || v.is_unspecified()),
        _ => true,
    })
}

/// Poignées sur la pile réseau du Nœud.
pub struct NodeNet {
    pub dht: DhtNode,
    pub blocks: BlockServer,
    pub nat: Arc<Mutex<NatState>>,
}

/// Démarre la pile réseau unique du Nœud.
pub async fn start(cfg: NetConfig) -> Result<NodeNet, String> {
    let net = |e: &dyn std::fmt::Display| e.to_string();
    let secret =
        identity::ed25519::SecretKey::try_from_bytes(cfg.node_seed).map_err(|e| net(&e))?;
    let keypair = identity::Keypair::from(identity::ed25519::Keypair::from(secret));
    let peer_id = keypair.public().to_peer_id();
    let limits = cfg.relay_limits;
    let (upnp_on, relay_on) = (cfg.upnp, cfg.relay_server);
    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| net(&e))?
        .with_quic()
        .with_relay_client(noise::Config::new, yamux::Config::default)
        .map_err(|e| net(&e))?
        .with_behaviour(|key, relay_client| {
            let id = key.public().to_peer_id();
            let mut kcfg = kad::Config::new(StreamProtocol::new(KAD_PROTOCOL));
            kcfg.set_record_filtering(kad::StoreInserts::FilterBoth);
            kcfg.set_publication_interval(None);
            kcfg.set_record_ttl(None);
            let mut kad = kad::Behaviour::with_config(id, MemoryStore::new(id), kcfg);
            kad.set_mode(Some(kad::Mode::Server));
            let relay_cfg = relay::Config {
                max_reservations: limits.max_reservations,
                max_circuit_duration: Duration::from_secs(limits.max_circuit_duration_s),
                max_circuit_bytes: limits.max_circuit_bytes,
                ..Default::default()
            };
            NodeBehaviour {
                kad,
                rr: request_response::Behaviour::new(
                    [(StreamProtocol::new(PROTOCOL), ProtocolSupport::Full)],
                    request_response::Config::default()
                        .with_request_timeout(Duration::from_secs(30)),
                ),
                identify: identify::Behaviour::new(
                    identify::Config::new(IDENTIFY_PROTOCOL.into(), key.public())
                        .with_agent_version(format!(
                            "p2p-storage-node/{}",
                            env!("CARGO_PKG_VERSION")
                        )),
                ),
                autonat: autonat::Behaviour::new(id, autonat::Config::default()),
                upnp: Toggle::from(upnp_on.then(upnp::tokio::Behaviour::default)),
                relay_server: Toggle::from(relay_on.then(|| relay::Behaviour::new(id, relay_cfg))),
                relay_client,
                dcutr: dcutr::Behaviour::new(id),
            }
        })
        .map_err(|e| net(&e))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    for a in &cfg.listen {
        swarm.listen_on(a.clone()).map_err(|e| net(&e))?;
        if let Some(q) = quic_of(a) {
            let _ = swarm.listen_on(q);
        }
    }
    for a in &cfg.external {
        swarm.add_external_address(a.clone());
    }
    for addr in &cfg.bootstrap {
        if let Some(Protocol::P2p(peer)) = addr.iter().last() {
            swarm.behaviour_mut().kad.add_address(&peer, addr.clone());
            let _ = swarm.dial(new_port(addr.clone()));
        }
    }
    if !cfg.bootstrap.is_empty() {
        let _ = swarm.behaviour_mut().kad.bootstrap();
    }
    let nat = Arc::new(Mutex::new(NatState {
        status: "inconnu".into(),
        upnp: if upnp_on {
            "recherche de la box…".into()
        } else {
            "désactivé".into()
        },
        ..Default::default()
    }));
    let (dtx, drx) = mpsc::channel(64);
    let (btx, brx) = mpsc::channel(64);
    let dl = DhtLoop::new(cfg.vdf, cfg.clock.clone());
    let el = ExchangeLoop::new(peer_id, Some(cfg.service), cfg.clock);
    let opts = RunOpts {
        static_relays: cfg.relays,
        force_relay: cfg.force_relay,
        assume_listen_public: cfg.assume_listen_public,
    };
    tokio::spawn(run(swarm, drx, brx, dl, el, nat.clone(), opts));
    Ok(NodeNet {
        dht: DhtNode::from_parts(peer_id, dtx),
        blocks: BlockServer::from_parts(peer_id, btx),
        nat,
    })
}

struct RunOpts {
    static_relays: Vec<Multiaddr>,
    force_relay: bool,
    assume_listen_public: bool,
}

async fn run(
    mut swarm: Swarm<NodeBehaviour>,
    mut drx: mpsc::Receiver<DhtCommand>,
    mut brx: mpsc::Receiver<BlockCmd>,
    mut dl: DhtLoop,
    mut el: ExchangeLoop,
    nat: Arc<Mutex<NatState>>,
    opts: RunOpts,
) {
    let RunOpts {
        static_relays,
        force_relay,
        assume_listen_public,
    } = opts;
    let me = *swarm.local_peer_id();
    // Pairs capables de relayer, avec leurs adresses (Identify).
    let mut relay_capable: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();
    let mut relays_requested: HashSet<PeerId> = HashSet::new();
    // Relais choisis, en attente de connexion avant la réservation.
    let mut relays_pending: HashMap<PeerId, Multiaddr> = HashMap::new();
    let mut tick = tokio::time::interval(Duration::from_secs(20));
    let mut private = false;
    loop {
        tokio::select! {
            cmd = drx.recv() => match cmd {
                None => return,
                Some(c) => {
                    let listen = first_direct(&swarm);
                    dl.on_cmd(&mut swarm.behaviour_mut().kad, listen, c);
                }
            },
            cmd = brx.recv() => match cmd {
                None => return,
                Some(c) => el.on_cmd(&mut swarm, c),
            },
            _ = tick.tick() => {
                // Derrière un NAT (ou forcé) : réservations chez des relais.
                let active = nat.lock().unwrap().relayed.len();
                if (private || force_relay) && active < TARGET_RELAYS && relays_requested.len() < TARGET_RELAYS + 2 {
                    let mut candidates: Vec<Multiaddr> = static_relays.clone();
                    for (peer, addrs) in &relay_capable {
                        if relays_requested.contains(peer) {
                            continue;
                        }
                        let best = addrs.iter().find(|a| is_public(a) && !a.iter().any(|p| matches!(p, Protocol::P2pCircuit)))
                            .or_else(|| addrs.iter().find(|a| !a.iter().any(|p| matches!(p, Protocol::P2pCircuit) )));
                        if let Some(a) = best {
                            candidates.push(a.clone().with(Protocol::P2p(*peer)));
                        }
                    }
                    for c in candidates {
                        let Some(Protocol::P2p(peer)) = c.iter().last() else { continue };
                        if peer == me || !relays_requested.insert(peer) {
                            continue;
                        }
                        if swarm.is_connected(&peer) {
                            let _ = swarm.listen_on(c.with(Protocol::P2pCircuit));
                        } else {
                            relays_pending.insert(peer, c.clone());
                            let _ = swarm.dial(new_port(c));
                        }
                        if relays_requested.len() >= TARGET_RELAYS + active {
                            break;
                        }
                    }
                }
            },
            event = swarm.select_next_some() => match event {
                SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                    el.on_connected(&mut swarm, peer_id, endpoint.get_remote_address());
                    if let Some(c) = relays_pending.remove(&peer_id) {
                        let _ = swarm.listen_on(c.with(Protocol::P2pCircuit));
                    }
                }
                SwarmEvent::OutgoingConnectionError { peer_id: Some(p), error, .. } => {
                    el.on_dial_error(p, error.to_string());
                    if relays_pending.remove(&p).is_some() {
                        relays_requested.remove(&p); // nouvel essai au prochain tour
                    }
                }
                SwarmEvent::NewListenAddr { address, .. } => {
                    let circuit = address.iter().any(|p| matches!(p, Protocol::P2pCircuit));
                    {
                        let mut n = nat.lock().unwrap();
                        if circuit {
                            n.relayed.push(with_self(&address, me));
                        } else {
                            n.listen.push(address.to_string());
                        }
                    }
                    // Écoute directe sur une adresse publique : joignable tel quel.
                    if !circuit && (assume_listen_public || is_public(&address)) {
                        swarm.add_external_address(address);
                    }
                }
                SwarmEvent::ListenerClosed { addresses, reason: Err(e), .. } => {
                    if addresses.iter().any(|a| a.iter().any(|p| matches!(p, Protocol::P2pCircuit))) || addresses.is_empty() {
                        nat.lock().unwrap().relay_error = Some(e.to_string());
                    }
                }
                SwarmEvent::ListenerError { error, .. } => {
                    nat.lock().unwrap().relay_error = Some(error.to_string());
                }
                SwarmEvent::ExpiredListenAddr { address, .. } => {
                    let s = with_self(&address, me);
                    let mut n = nat.lock().unwrap();
                    n.relayed.retain(|a| *a != s);
                    n.listen.retain(|a| *a != address.to_string());
                }
                SwarmEvent::ExternalAddrConfirmed { address } => {
                    let s = with_self(&address, me);
                    let mut n = nat.lock().unwrap();
                    if !n.external.contains(&s) {
                        n.external.push(s);
                    }
                }
                SwarmEvent::ExternalAddrExpired { address } => {
                    let s = with_self(&address, me);
                    nat.lock().unwrap().external.retain(|a| *a != s);
                }
                SwarmEvent::Behaviour(ev) => match ev {
                    NodeBehaviourEvent::Kad(e) => dl.on_event(&mut swarm.behaviour_mut().kad, e),
                    NodeBehaviourEvent::Rr(e) => el.on_event(&mut swarm, e),
                    NodeBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. }) => {
                        if info.protocols.iter().any(|p| p.as_ref() == KAD_PROTOCOL) {
                            for a in &info.listen_addrs {
                                swarm.behaviour_mut().kad.add_address(&peer_id, a.clone());
                            }
                        }
                        if info.protocols.iter().any(|p| p.as_ref() == RELAY_HOP) {
                            relay_capable.insert(peer_id, info.listen_addrs.clone());
                        }
                    }
                    NodeBehaviourEvent::Autonat(autonat::Event::StatusChanged { new, .. }) => {
                        let mut n = nat.lock().unwrap();
                        match new {
                            autonat::NatStatus::Public(_) => {
                                n.status = "public".into();
                                private = false;
                            }
                            autonat::NatStatus::Private => {
                                n.status = "derrière un NAT".into();
                                private = true;
                            }
                            autonat::NatStatus::Unknown => n.status = "inconnu".into(),
                        }
                    }
                    NodeBehaviourEvent::Upnp(e) => {
                        nat.lock().unwrap().upnp = match e {
                            upnp::Event::NewExternalAddr(a) => format!("port ouvert : {a}"),
                            upnp::Event::ExpiredExternalAddr(a) => format!("redirection expirée : {a}"),
                            upnp::Event::GatewayNotFound => "aucune box UPnP trouvée".into(),
                            upnp::Event::NonRoutableGateway => "box non exposée à Internet (double NAT ?)".into(),
                        };
                    }
                    NodeBehaviourEvent::RelayClient(relay::client::Event::ReservationReqAccepted { relay_peer_id, .. }) => {
                        nat.lock().unwrap().relay_error = None;
                        let _ = relay_peer_id;
                    }
                    NodeBehaviourEvent::RelayServer(relay::Event::CircuitReqAccepted { .. }) => {
                        nat.lock().unwrap().relay_circuits_served += 1;
                    }
                    NodeBehaviourEvent::Dcutr(e) => {
                        let mut n = nat.lock().unwrap();
                        if e.result.is_ok() {
                            n.hole_punch_ok += 1;
                        } else {
                            n.hole_punch_failed += 1;
                        }
                    }
                    _ => {}
                },
                _ => {}
            }
        }
    }
}
