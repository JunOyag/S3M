//! Adaptateur Kademlia du Nœud — id `network.dht-directory`, component
//! `node` (spec V3). Réf. spec : docs/01-network-dht/dht-directory.md.
//!
//! - Transport : TCP + Noise + Yamux (libp2p). L'identité libp2p du Nœud est
//!   sa clé Ed25519 `priv_node` : `PeerId` dérive de `pub_node`.
//! - Amorçage : liste d'adresses `/ip4/…/tcp/…/p2p/<PeerId>` fournie par la
//!   configuration (le mécanisme complet relève de `network.bootstrap`).
//! - **Tout enregistrement est vérifié avant stockage**, qu'il vienne d'un
//!   pair (`StoreInserts::FilterBoth`) ou d'un `put` local, et à nouveau à la
//!   lecture : règles de `p2p_storage_protocol::dht::verify_envelope`.
//! - Pas de suppression ; l'expiration suit le TTL du type d'entrée ; la
//!   republication est à la charge du propriétaire (pas de republication
//!   automatique Kademlia).

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures::StreamExt;
use libp2p::kad::store::{MemoryStore, RecordStore};
use libp2p::kad::{self, GetRecordOk, QueryResult, Quorum, Record, RecordKey};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{identity, noise, tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm};
use p2p_storage_core::vdf::VdfProof;
use p2p_storage_core::CoreError;
use p2p_storage_protocol::dht::{accept_record, DhtError};
use tokio::sync::{mpsc, oneshot};

/// Protocole Kademlia propre au réseau P2P-Storage.
pub const KAD_PROTOCOL: &str = "/p2p-storage/kad/1.0.0";

/// Vérificateur VDF partagé entre tâches (`chiavdf` en production).
pub type SharedVdfVerifier =
    Arc<dyn Fn(&[u8; 33], &VdfProof) -> Result<bool, CoreError> + Send + Sync>;

/// Vérificateur de production : `chiavdf` (feature `vdf` de `impl/core`).
pub fn chiavdf_verifier() -> SharedVdfVerifier {
    Arc::new(p2p_storage_core::vdf::verify_identity_proof)
}

/// Configuration de l'adaptateur.
pub struct DhtConfig {
    /// Graine Ed25519 du Nœud (`priv_node`).
    pub node_seed: [u8; 32],
    /// Adresse d'écoute, ex. `/ip4/0.0.0.0/tcp/4001`.
    pub listen: Multiaddr,
    /// Pairs d'amorçage `/ip4/…/tcp/…/p2p/<PeerId>`.
    pub bootstrap: Vec<Multiaddr>,
    /// Vérificateur VDF.
    pub vdf: SharedVdfVerifier,
    /// Horloge Unix (secondes) — injectable pour les tests.
    pub clock: Arc<dyn Fn() -> u64 + Send + Sync>,
}

/// Horloge système.
pub fn system_clock() -> Arc<dyn Fn() -> u64 + Send + Sync> {
    Arc::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    })
}

/// Erreurs de l'adaptateur.
#[derive(Debug, thiserror::Error)]
pub enum DhtNodeError {
    #[error("entrée rejetée : {0}")]
    Rejected(#[from] DhtError),
    #[error("réseau : {0}")]
    Network(String),
    #[error("adaptateur arrêté")]
    Stopped,
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    kad: kad::Behaviour<MemoryStore>,
}

pub(crate) enum Command {
    Put(Vec<u8>, Vec<u8>, oneshot::Sender<Result<(), DhtNodeError>>),
    Get(Vec<u8>, oneshot::Sender<Option<Vec<u8>>>),
    ListenAddr(oneshot::Sender<Option<Multiaddr>>),
    /// Pairs les plus proches d'une clé (découverte de partenaires).
    Closest(Vec<u8>, oneshot::Sender<Vec<PeerId>>),
}

/// Poignée sur l'adaptateur DHT (la boucle réseau tourne dans une tâche tokio).
#[derive(Clone)]
pub struct DhtNode {
    peer_id: PeerId,
    tx: mpsc::Sender<Command>,
}

impl DhtNode {
    /// Démarre l'adaptateur : écoute, ajoute les pairs d'amorçage, lance la
    /// boucle réseau.
    pub async fn start(config: DhtConfig) -> Result<Self, DhtNodeError> {
        let net = |e: &dyn std::fmt::Display| DhtNodeError::Network(e.to_string());
        let secret =
            identity::ed25519::SecretKey::try_from_bytes(config.node_seed).map_err(|e| net(&e))?;
        let keypair = identity::Keypair::from(identity::ed25519::Keypair::from(secret));
        let peer_id = keypair.public().to_peer_id();
        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| net(&e))?
            .with_behaviour(|key| {
                let id = key.public().to_peer_id();
                let mut cfg = kad::Config::new(StreamProtocol::new(KAD_PROTOCOL));
                cfg.set_record_filtering(kad::StoreInserts::FilterBoth);
                cfg.set_publication_interval(None);
                cfg.set_record_ttl(None);
                let mut kad = kad::Behaviour::with_config(id, MemoryStore::new(id), cfg);
                kad.set_mode(Some(kad::Mode::Server));
                Behaviour { kad }
            })
            .map_err(|e| net(&e))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();
        swarm
            .listen_on(config.listen.clone())
            .map_err(|e| net(&e))?;
        for addr in &config.bootstrap {
            if let Some(Protocol::P2p(peer)) = addr.iter().last() {
                swarm.behaviour_mut().kad.add_address(&peer, addr.clone());
            }
        }
        if !config.bootstrap.is_empty() {
            let _ = swarm.behaviour_mut().kad.bootstrap();
        }
        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(run(swarm, rx, config.vdf, config.clock));
        Ok(Self { peer_id, tx })
    }

    /// Poignée sur une boucle réseau existante (`crate::net`).
    pub(crate) fn from_parts(peer_id: PeerId, tx: mpsc::Sender<Command>) -> Self {
        Self { peer_id, tx }
    }

    /// `PeerId` libp2p (dérivé de `pub_node`).
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Première adresse d'écoute effective, suffixée de `/p2p/<PeerId>`.
    pub async fn listen_addr(&self) -> Option<Multiaddr> {
        for _ in 0..50 {
            let (tx, rx) = oneshot::channel();
            self.tx.send(Command::ListenAddr(tx)).await.ok()?;
            if let Some(a) = rx.await.ok()? {
                return Some(a.with(Protocol::P2p(self.peer_id)));
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        None
    }

    /// Publie une enveloppe sous `key`, après vérification locale.
    pub async fn put(&self, key: Vec<u8>, envelope: Vec<u8>) -> Result<(), DhtNodeError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Command::Put(key, envelope, tx))
            .await
            .map_err(|_| DhtNodeError::Stopped)?;
        rx.await.map_err(|_| DhtNodeError::Stopped)?
    }

    /// Pairs serveurs les plus proches d'une clé, table de routage comprise
    /// (`protocols.partenariat-automatique` § Découverte).
    pub async fn closest_peers(&self, key: Vec<u8>) -> Result<Vec<PeerId>, DhtNodeError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Command::Closest(key, tx))
            .await
            .map_err(|_| DhtNodeError::Stopped)?;
        rx.await.map_err(|_| DhtNodeError::Stopped)
    }

    /// Lit l'enveloppe valide publiée sous `key` (locale ou réseau).
    pub async fn get(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>, DhtNodeError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Command::Get(key, tx))
            .await
            .map_err(|_| DhtNodeError::Stopped)?;
        rx.await.map_err(|_| DhtNodeError::Stopped)
    }
}

/// Règle d'acceptation : `p2p_storage_protocol::dht::accept_record`.
fn accept(
    key: &[u8],
    envelope: &[u8],
    previous: Option<&[u8]>,
    vdf: &SharedVdfVerifier,
    now: u64,
) -> Result<u64, DhtError> {
    accept_record(key, envelope, previous, now, &|id, p| vdf(id, p))
}

fn expiry_instant(expires_at: u64, now: u64) -> Instant {
    Instant::now() + Duration::from_secs(expires_at.saturating_sub(now))
}

type PendingGets =
    std::collections::HashMap<kad::QueryId, (Vec<u8>, oneshot::Sender<Option<Vec<u8>>>)>;
type PendingClosest = std::collections::HashMap<kad::QueryId, oneshot::Sender<Vec<PeerId>>>;
type PendingPuts =
    std::collections::HashMap<kad::QueryId, oneshot::Sender<Result<(), DhtNodeError>>>;

/// Machine d'état de l'adaptateur DHT, indépendante du swarm qui la porte
/// (swarm dédié, ou swarm unique du Nœud : `crate::net`).
pub(crate) struct DhtLoop {
    vdf: SharedVdfVerifier,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    pending_get: PendingGets,
    pending_put: PendingPuts,
    pending_closest: PendingClosest,
}

impl DhtLoop {
    pub(crate) fn new(vdf: SharedVdfVerifier, clock: Arc<dyn Fn() -> u64 + Send + Sync>) -> Self {
        Self {
            vdf,
            clock,
            pending_get: Default::default(),
            pending_put: Default::default(),
            pending_closest: Default::default(),
        }
    }

    /// Commande d'une poignée `DhtNode` ; `listen` : adresse d'écoute.
    pub(crate) fn on_cmd(
        &mut self,
        kad: &mut kad::Behaviour<MemoryStore>,
        listen: Option<Multiaddr>,
        cmd: Command,
    ) {
        match cmd {
            Command::ListenAddr(reply) => {
                let _ = reply.send(listen);
            }
            Command::Closest(key, reply) => {
                let id = kad.get_closest_peers(key);
                self.pending_closest.insert(id, reply);
            }
            Command::Put(key, env, reply) => {
                let now = (self.clock)();
                let rkey = RecordKey::new(&key);
                let previous = kad.store_mut().get(&rkey).map(|r| r.value.clone());
                match accept(&key, &env, previous.as_deref(), &self.vdf, now) {
                    Err(e) => {
                        let _ = reply.send(Err(e.into()));
                    }
                    Ok(exp) => {
                        let mut record = Record::new(rkey, env);
                        record.expires = Some(expiry_instant(exp, now));
                        match kad.put_record(record, Quorum::One) {
                            Ok(id) => {
                                self.pending_put.insert(id, reply);
                            }
                            Err(e) => {
                                let _ = reply.send(Err(DhtNodeError::Network(e.to_string())));
                            }
                        }
                    }
                }
            }
            Command::Get(key, reply) => {
                let rkey = RecordKey::new(&key);
                let now = (self.clock)();
                let local = kad.store_mut().get(&rkey).map(|r| r.value.clone());
                if let Some(v) = local.filter(|v| accept(&key, v, None, &self.vdf, now).is_ok()) {
                    let _ = reply.send(Some(v));
                } else {
                    let id = kad.get_record(rkey);
                    self.pending_get.insert(id, (key, reply));
                }
            }
        }
    }

    /// Événement Kademlia.
    pub(crate) fn on_event(&mut self, kad: &mut kad::Behaviour<MemoryStore>, ev: kad::Event) {
        let (vdf, clock) = (&self.vdf, &self.clock);
        match ev {
            kad::Event::OutboundQueryProgressed {
                id,
                result: QueryResult::GetClosestPeers(r),
                ..
            } => {
                if let Some(reply) = self.pending_closest.remove(&id) {
                    let mut peers: Vec<PeerId> = match r {
                        Ok(ok) => ok.peers.iter().map(|p| p.peer_id).collect(),
                        Err(kad::GetClosestPeersError::Timeout { peers, .. }) => {
                            peers.iter().map(|p| p.peer_id).collect()
                        }
                    };
                    for b in kad.kbuckets() {
                        peers.extend(b.iter().map(|e| *e.node.key.preimage()));
                    }
                    peers.sort();
                    peers.dedup();
                    let _ = reply.send(peers);
                }
            }
            // Enregistrement poussé par un pair : vérifié avant stockage.
            kad::Event::InboundRequest {
                request:
                    kad::InboundRequest::PutRecord {
                        record: Some(record),
                        ..
                    },
            } => {
                let now = clock();
                let store = kad.store_mut();
                let previous = store.get(&record.key).map(|r| r.value.clone());
                if let Ok(exp) = accept(
                    record.key.as_ref(),
                    &record.value,
                    previous.as_deref(),
                    vdf,
                    now,
                ) {
                    let mut r = record;
                    r.expires = Some(expiry_instant(exp, now));
                    let _ = store.put(r);
                }
            }
            kad::Event::OutboundQueryProgressed {
                id, result, step, ..
            } => match result {
                QueryResult::GetRecord(Ok(GetRecordOk::FoundRecord(peer_record))) => {
                    let valid = self.pending_get.get(&id).map(|(key, _)| {
                        accept(key, &peer_record.record.value, None, vdf, clock()).is_ok()
                    });
                    if valid == Some(true) {
                        if let Some((_, reply)) = self.pending_get.remove(&id) {
                            let _ = reply.send(Some(peer_record.record.value));
                        }
                        if let Some(mut q) = kad.query_mut(&id) {
                            q.finish();
                        }
                    } else if step.last {
                        if let Some((_, reply)) = self.pending_get.remove(&id) {
                            let _ = reply.send(None);
                        }
                    }
                }
                QueryResult::GetRecord(_) => {
                    if step.last {
                        if let Some((_, reply)) = self.pending_get.remove(&id) {
                            let _ = reply.send(None);
                        }
                    }
                }
                QueryResult::PutRecord(_) => {
                    // Stocké localement dans tous les cas ; l'échec de
                    // réplication (aucun pair joignable) n'est pas fatal.
                    if let Some(reply) = self.pending_put.remove(&id) {
                        let _ = reply.send(Ok(()));
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }
}

async fn run(
    mut swarm: Swarm<Behaviour>,
    mut rx: mpsc::Receiver<Command>,
    vdf: SharedVdfVerifier,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
) {
    let mut dl = DhtLoop::new(vdf, clock);
    loop {
        tokio::select! {
            cmd = rx.recv() => match cmd {
                None => return,
                Some(c) => {
                    let listen = swarm.listeners().next().cloned();
                    dl.on_cmd(&mut swarm.behaviour_mut().kad, listen, c);
                }
            },
            event = swarm.select_next_some() => {
                if let SwarmEvent::Behaviour(BehaviourEvent::Kad(ev)) = event {
                    dl.on_event(&mut swarm.behaviour_mut().kad, ev);
                }
            }
        }
    }
}

/// Suppression explicite d'une entrée DispersalManifest
/// (`protocols.suppression-dispersal`) — réservée au Nœud : seul ce
/// composant expose la fonction ; le Connecteur n'en a pas.
pub async fn delete_dispersal_entry(
    node: &DhtNode,
    dht_key: Vec<u8>,
    sig_priv_dispersal: &[u8; 32],
    now: u64,
) -> Result<(), DhtNodeError> {
    let env = p2p_storage_protocol::dht::dispersal_deletion_envelope(sig_priv_dispersal, now);
    node.put(dht_key, env).await
}
