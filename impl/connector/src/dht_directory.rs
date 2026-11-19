//! Adaptateur Kademlia du Connecteur — id `network.dht-directory`, component
//! `connector` (spec V3). Réf. spec : docs/01-network-dht/dht-directory.md.
//!
//! - **Client uniquement** : aucune adresse d'écoute (« le Connecteur
//!   n'accepte aucune connexion entrante »), mode Kademlia `Client` — il ne
//!   stocke ni ne sert d'enregistrement pour les autres.
//! - **Identité libp2p éphémère**, tirée au hasard à chaque démarrage :
//!   le `PeerId` ne révèle jamais `pub_user`.
//! - Connexions sortantes vers les Nœuds d'amorçage (TCP + Noise + Yamux).
//! - Toute entrée lue ou publiée est vérifiée par
//!   `p2p_storage_protocol::dht::accept_record`, la règle du Nœud.

use std::collections::HashMap;
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

/// Protocole Kademlia du réseau (identique au Nœud).
pub const KAD_PROTOCOL: &str = "/p2p-storage/kad/1.0.0";

/// Vérificateur VDF partagé (`chiavdf` en production).
pub type SharedVdfVerifier =
    Arc<dyn Fn(&[u8; 33], &VdfProof) -> Result<bool, CoreError> + Send + Sync>;

/// Vérificateur de production : `chiavdf` (feature `vdf` de `impl/core`).
pub fn chiavdf_verifier() -> SharedVdfVerifier {
    Arc::new(p2p_storage_core::vdf::verify_identity_proof)
}

/// Horloge Unix (secondes), injectable pour les tests.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// Horloge système.
pub fn system_clock() -> Clock {
    Arc::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    })
}

/// Configuration du client DHT.
pub struct DhtClientConfig {
    /// Nœuds d'amorçage `/ip4/…/tcp/…/p2p/<PeerId>` (au moins un).
    pub bootstrap: Vec<Multiaddr>,
    pub vdf: SharedVdfVerifier,
    pub clock: Clock,
}

/// Erreurs du client.
#[derive(Debug, thiserror::Error)]
pub enum DhtClientError {
    #[error("entrée rejetée : {0}")]
    Rejected(#[from] DhtError),
    #[error("réseau : {0}")]
    Network(String),
    #[error("aucun Nœud d'amorçage configuré")]
    NoBootstrap,
    #[error("client arrêté")]
    Stopped,
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    kad: kad::Behaviour<MemoryStore>,
}

enum Command {
    Put(
        Vec<u8>,
        Vec<u8>,
        oneshot::Sender<Result<(), DhtClientError>>,
    ),
    Get(Vec<u8>, oneshot::Sender<Option<Vec<u8>>>),
    Listeners(oneshot::Sender<usize>),
}

type PendingGets = HashMap<kad::QueryId, (Vec<u8>, oneshot::Sender<Option<Vec<u8>>>)>;
type PendingPuts = HashMap<kad::QueryId, oneshot::Sender<Result<(), DhtClientError>>>;

/// Poignée sur le client DHT.
#[derive(Clone)]
pub struct DhtClient {
    peer_id: PeerId,
    tx: mpsc::Sender<Command>,
}

impl DhtClient {
    /// Démarre le client : identité éphémère, connexions aux Nœuds
    /// d'amorçage, boucle réseau.
    pub async fn start(config: DhtClientConfig) -> Result<Self, DhtClientError> {
        if config.bootstrap.is_empty() {
            return Err(DhtClientError::NoBootstrap);
        }
        let net = |e: &dyn std::fmt::Display| DhtClientError::Network(e.to_string());
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|e| net(&e))?;
        let secret = identity::ed25519::SecretKey::try_from_bytes(seed).map_err(|e| net(&e))?;
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
                kad.set_mode(Some(kad::Mode::Client));
                Behaviour { kad }
            })
            .map_err(|e| net(&e))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();
        for addr in &config.bootstrap {
            if let Some(Protocol::P2p(peer)) = addr.iter().last() {
                swarm.behaviour_mut().kad.add_address(&peer, addr.clone());
            }
        }
        let _ = swarm.behaviour_mut().kad.bootstrap();
        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(run(swarm, rx, config.vdf, config.clock));
        Ok(Self { peer_id, tx })
    }

    /// `PeerId` éphémère de la session.
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Nombre d'adresses d'écoute (toujours 0 : client uniquement).
    pub async fn listener_count(&self) -> Result<usize, DhtClientError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Command::Listeners(tx))
            .await
            .map_err(|_| DhtClientError::Stopped)?;
        rx.await.map_err(|_| DhtClientError::Stopped)
    }

    /// Publie une enveloppe sous `key`, après vérification locale.
    pub async fn put(&self, key: Vec<u8>, envelope: Vec<u8>) -> Result<(), DhtClientError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Command::Put(key, envelope, tx))
            .await
            .map_err(|_| DhtClientError::Stopped)?;
        rx.await.map_err(|_| DhtClientError::Stopped)?
    }

    /// Lit sur le réseau la première enveloppe valide publiée sous `key`.
    pub async fn get(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>, DhtClientError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Command::Get(key, tx))
            .await
            .map_err(|_| DhtClientError::Stopped)?;
        rx.await.map_err(|_| DhtClientError::Stopped)
    }
}

async fn run(
    mut swarm: Swarm<Behaviour>,
    mut rx: mpsc::Receiver<Command>,
    vdf: SharedVdfVerifier,
    clock: Clock,
) {
    let mut gets: PendingGets = HashMap::new();
    let mut puts: PendingPuts = HashMap::new();
    let check = |key: &[u8], env: &[u8], prev: Option<&[u8]>, now| {
        accept_record(key, env, prev, now, &|id, p| vdf(id, p))
    };
    loop {
        tokio::select! {
            cmd = rx.recv() => match cmd {
                None => return,
                Some(Command::Listeners(reply)) => {
                    let _ = reply.send(swarm.listeners().count());
                }
                Some(Command::Put(key, env, reply)) => {
                    let now = clock();
                    let rkey = RecordKey::new(&key);
                    let prev = swarm.behaviour_mut().kad.store_mut().get(&rkey).map(|r| r.value.clone());
                    match check(&key, &env, prev.as_deref(), now) {
                        Err(e) => { let _ = reply.send(Err(e.into())); }
                        Ok(exp) => {
                            let mut record = Record::new(rkey, env);
                            record.expires = Some(Instant::now() + Duration::from_secs(exp.saturating_sub(now)));
                            match swarm.behaviour_mut().kad.put_record(record, Quorum::One) {
                                Ok(id) => { puts.insert(id, reply); }
                                Err(e) => { let _ = reply.send(Err(DhtClientError::Network(e.to_string()))); }
                            }
                        }
                    }
                }
                Some(Command::Get(key, reply)) => {
                    let id = swarm.behaviour_mut().kad.get_record(RecordKey::new(&key));
                    gets.insert(id, (key, reply));
                }
            },
            event = swarm.select_next_some() => {
                let SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed { id, result, step, .. })) = event else { continue };
                match result {
                    QueryResult::GetRecord(Ok(GetRecordOk::FoundRecord(found))) => {
                        let valid = gets.get(&id).is_some_and(|(key, _)| check(key, &found.record.value, None, clock()).is_ok());
                        if valid {
                            if let Some((_, reply)) = gets.remove(&id) { let _ = reply.send(Some(found.record.value)); }
                            if let Some(mut q) = swarm.behaviour_mut().kad.query_mut(&id) { q.finish(); }
                        } else if step.last {
                            if let Some((_, reply)) = gets.remove(&id) { let _ = reply.send(None); }
                        }
                    }
                    QueryResult::GetRecord(_) if step.last => {
                        if let Some((_, reply)) = gets.remove(&id) { let _ = reply.send(None); }
                    }
                    QueryResult::PutRecord(r) => {
                        if let Some(reply) = puts.remove(&id) {
                            let _ = reply.send(r.map(|_| ()).map_err(|e| DhtClientError::Network(e.to_string())));
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}
