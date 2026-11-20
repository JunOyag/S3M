//! Recherche des Nœuds S3m du réseau local (mDNS) — id `network.bootstrap`
//! § Découverte sur le réseau local, utilisée par l'assistant de premier
//! lancement (`deploiement.packaging` § Application de la barre des tâches).
//!
//! Écoute les annonces mDNS pendant `duration`, puis confirme chaque
//! candidat par un `Probe` (`protocols.echange-blocs`). Le `node_id` se
//! déduit du `PeerId` annoncé (clé Ed25519).

use std::collections::BTreeMap;
use std::time::Duration;

use futures::StreamExt;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::SwarmEvent;
use libp2p::{identity, mdns, noise, tcp, yamux, Multiaddr, PeerId};
use s3m_protocol::exchange::{Body, Request, Response};

use crate::exchange::BlockClient;

/// Nœud trouvé sur le réseau local.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundNode {
    pub node_id: [u8; 32],
    /// Adresse d'échange de blocs retenue (TCP IPv4 de préférence).
    pub addr: String,
    pub accepting_partners: bool,
    /// Nœud sous identité temporaire, à configurer par appairage
    /// (`deploiement.appairage-admin`) ; `addr` est alors son adresse
    /// d'administration.
    pub to_configure: bool,
}

/// `pub_node` d'un `PeerId` Ed25519.
pub fn node_id_of(peer: &PeerId) -> Option<[u8; 32]> {
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

fn rank(a: &Multiaddr) -> u8 {
    let ip4 = a
        .iter()
        .any(|p| matches!(p, Protocol::Ip4(v) if !v.is_loopback()));
    let tcp = a.iter().any(|p| matches!(p, Protocol::Tcp(_)));
    match (ip4, tcp) {
        (true, true) => 0,
        (true, false) => 1,
        (false, true) => 2,
        _ => 3,
    }
}

/// Recherche les Nœuds du réseau local ; seuls ceux qui répondent à un
/// `Probe` sont rendus.
pub async fn scan(duration: Duration) -> Result<Vec<FoundNode>, String> {
    let net = |e: &dyn std::fmt::Display| e.to_string();
    let mut swarm = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| net(&e))?
        .with_behaviour(|key| {
            mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
        })
        .map_err(|e| net(&e))?
        .build();
    let mut found: BTreeMap<PeerId, Vec<Multiaddr>> = BTreeMap::new();
    let deadline = tokio::time::sleep(duration);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => break,
            ev = swarm.select_next_some() => {
                if let SwarmEvent::Behaviour(mdns::Event::Discovered(list)) = ev {
                    for (peer, addr) in list {
                        found.entry(peer).or_default().push(addr);
                    }
                }
            }
        }
    }
    drop(swarm);
    let client = BlockClient::start().map_err(|e| e.to_string())?;
    let admin = crate::admin_client::AdminClient::start()?;
    let mut out = Vec::new();
    for (peer, mut addrs) in found {
        let Some(node_id) = node_id_of(&peer) else {
            continue;
        };
        addrs.sort_by_key(rank);
        let mut probed = false;
        for a in addrs.clone() {
            let a = a.with(Protocol::P2p(peer));
            let req = Request {
                credential: None,
                body: Body::Probe { nonce: vec![1; 16] },
            };
            let r =
                tokio::time::timeout(Duration::from_secs(3), client.request(a.clone(), req)).await;
            if let Ok(Ok(Response::ProbeReply {
                accepting_partners, ..
            })) = r
            {
                out.push(FoundNode {
                    node_id,
                    addr: a.to_string(),
                    accepting_partners,
                    to_configure: false,
                });
                probed = true;
                break;
            }
        }
        if probed {
            continue;
        }
        // Pas de `Probe` : Nœud sous identité temporaire ?
        for a in addrs {
            let a = a.with(Protocol::P2p(peer));
            let r = tokio::time::timeout(Duration::from_secs(3), admin.hello(&a)).await;
            if let Ok(Ok(mode)) = r {
                if mode == s3m_protocol::admin::MODE_SETUP {
                    out.push(FoundNode {
                        node_id,
                        addr: a.to_string(),
                        accepting_partners: false,
                        to_configure: true,
                    });
                }
                break;
            }
        }
    }
    Ok(out)
}
