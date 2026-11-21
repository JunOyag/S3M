//! Espace de secours — id `protocols.espace-secours`, partie `connector`
//! (Phase 4). Réf. spec : docs/04-protocols/espace-secours.md.
//!
//! - Partenaires de secours : les `n_secours` Nœuds les plus proches de
//!   l'identité **Utilisateur** au sens XOR (pas du Nœud hébergeur, exclu).
//! - Dispersion sans erasure coding : blocs répartis à parts égales,
//!   charge maximale `Q_max / n_secours` par partenaire.
//! - Écriture de l'`EmergencyManifest` : lecture, **fusion sans perte**,
//!   publication avec `seq + 1` (les pairs rejettent `seq ≤` le leur).
//! - Réconciliation idempotente : une mutation n'est appliquée que si tous
//!   ses blocs sont présents sur le Nœud, et jamais deux fois.
//! - Dimensionnement : `E_secours = U_backup × Q_max / n_secours`.

use std::collections::BTreeSet;

use crate::fs::BlockHash;
use crate::write_queue::{Op, Queued, BLOCK_BYTES};

/// Nombre de partenaires de secours par défaut.
pub const DEFAULT_N_SECOURS: usize = 4;

/// Erreurs de l'espace de secours.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum EmergencyError {
    #[error("pas assez de partenaires candidats")]
    NotEnoughPartners,
    #[error("charge maximale par partenaire dépassée")]
    PartnerOverloaded,
}

fn xor_distance(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut d = [0u8; 32];
    for i in 0..32 {
        d[i] = a[i] ^ b[i];
    }
    d
}

/// Sélectionne les `n` candidats les plus proches de `user_identity` au
/// sens XOR, hors Nœud hébergeur.
pub fn select_partners(
    user_identity: &[u8; 32],
    host_node: &[u8; 32],
    candidates: &[[u8; 32]],
    n: usize,
) -> Result<Vec<[u8; 32]>, EmergencyError> {
    let mut c: Vec<_> = candidates
        .iter()
        .filter(|c| *c != host_node)
        .copied()
        .collect();
    c.sort_by_key(|id| xor_distance(id, user_identity));
    c.dedup();
    if c.len() < n {
        return Err(EmergencyError::NotEnoughPartners);
    }
    c.truncate(n);
    Ok(c)
}

/// Répartit les blocs à parts égales (tour de rôle) entre `n` partenaires,
/// dans la limite de `q_max / n` octets chacun. Rend l'indice de partenaire
/// de chaque bloc.
pub fn assign_blocks(blocks: usize, n: usize, q_max: u64) -> Result<Vec<usize>, EmergencyError> {
    if n == 0 {
        return Err(EmergencyError::NotEnoughPartners);
    }
    let per_partner = blocks.div_ceil(n) as u64 * BLOCK_BYTES;
    if per_partner > q_max / n as u64 {
        return Err(EmergencyError::PartnerOverloaded);
    }
    Ok((0..blocks).map(|i| i % n).collect())
}

/// Contenu (déchiffré) d'un `EmergencyManifest`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EmergencyState {
    pub partners: BTreeSet<[u8; 32]>,
    /// `(block_hash, node_id du partenaire)`.
    pub blocks: BTreeSet<(BlockHash, [u8; 32])>,
    pub mutations: Vec<Queued>,
    pub base_fs_root_hash: BlockHash,
}

/// Lecture-fusion-écriture : fusionne `mine` dans l'entrée courante
/// (`current = (seq, état)` si elle existe) sans perdre aucun bloc,
/// partenaire ni mutation ; rend `(seq + 1, état fusionné)`.
pub fn merge(
    current: Option<(u64, &EmergencyState)>,
    mine: &EmergencyState,
) -> (u64, EmergencyState) {
    let (seq, mut out) = match current {
        Some((s, st)) => (s, st.clone()),
        None => (
            0,
            EmergencyState {
                base_fs_root_hash: mine.base_fs_root_hash,
                ..Default::default()
            },
        ),
    };
    out.partners.extend(mine.partners.iter().copied());
    out.blocks.extend(mine.blocks.iter().copied());
    for m in &mine.mutations {
        if !out.mutations.contains(m) {
            out.mutations.push(m.clone());
        }
    }
    out.mutations.sort_by_key(|m| m.timestamp);
    (seq + 1, out)
}

/// Réconciliation FS idempotente : mutations à appliquer, par timestamp
/// croissant, en sautant celles déjà appliquées (`applied`) et en refusant
/// toute mutation référençant un bloc absent du Nœud.
pub fn reconcile<'a>(
    state: &'a EmergencyState,
    applied: &dyn Fn(&Queued) -> bool,
    node_has_block: &dyn Fn(&BlockHash) -> bool,
) -> Vec<&'a Queued> {
    let mut v: Vec<_> = state
        .mutations
        .iter()
        .filter(|m| !applied(m))
        .filter(|m| match &m.op {
            Op::WriteBlock { block_hash } => node_has_block(block_hash),
            Op::UpdateEntry { entry } => node_has_block(&entry.first_block_hash),
            Op::DeleteEntry { .. } => true,
        })
        .collect();
    v.sort_by_key(|m| m.timestamp);
    v
}

/// `E_secours = U_backup × (Q_max / n_secours)` (octets).
pub fn emergency_capacity(u_backup: u64, q_max: u64, n_secours: u64) -> u64 {
    u_backup * (q_max / n_secours)
}

// ------------------------------------------------------------- réseau

use libp2p::{Multiaddr, PeerId};
use s3m_protocol::emergency::{EmergencyKeys, Partner};
use s3m_protocol::exchange::{
    emergency_deposit_signature, emergency_release, Body, Credential, Request, Response,
    MAX_RELEASE_HASHES,
};

use crate::dht_directory::DhtClient;
use crate::exchange::{BlockClient, ExchangeError};

/// Identité de dépôt : identité VDF de l'Utilisateur et clés de secours.
pub struct DepositIdentity {
    pub sig_priv_user: [u8; 32],
    pub sig_pub_user: [u8; 32],
    pub proof: s3m_core::vdf::VdfProof,
    pub keys: EmergencyKeys,
}

/// Partenaire de secours candidat, joignable à `addr`.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub partner: Partner,
    pub addr: Multiaddr,
}

/// `PeerId` d'un Nœud (dérivé de `pub_node`).
pub fn peer_of_node(node_id: &[u8; 32]) -> Option<PeerId> {
    let k = libp2p::identity::ed25519::PublicKey::try_from_bytes(node_id).ok()?;
    Some(PeerId::from(libp2p::identity::PublicKey::from(k)))
}

/// `pub_node` d'un `PeerId` de Nœud.
pub fn node_of_peer(peer: &PeerId) -> Option<[u8; 32]> {
    let mh: &libp2p::multihash::Multihash<64> = peer.as_ref();
    let k = libp2p::identity::PublicKey::try_decode_protobuf(mh.digest()).ok()?;
    Some(k.try_into_ed25519().ok()?.to_bytes())
}

fn with_peer(ip: &str, port: u16, node_id: &[u8; 32]) -> Option<Multiaddr> {
    let proto = if ip.contains(':') { "ip6" } else { "ip4" };
    format!("/{proto}/{ip}/tcp/{port}/p2p/{}", peer_of_node(node_id)?)
        .parse()
        .ok()
}

/// Adresses d'un Nœud publiées dans son entrée DHT, directe d'abord.
pub async fn node_addrs(
    dht: &DhtClient,
    node_id: &[u8; 32],
) -> (Option<(String, u16)>, Vec<Multiaddr>) {
    let Some(env) = dht.get(node_id.to_vec()).await.ok().flatten() else {
        return (None, Vec::new());
    };
    let Some((addrs, direct)) = s3m_protocol::entries::node_entry_addrs(&env) else {
        return (None, Vec::new());
    };
    let mut out: Vec<Multiaddr> = direct
        .as_ref()
        .and_then(|(ip, port)| with_peer(ip, *port, node_id))
        .into_iter()
        .collect();
    out.extend(addrs.iter().filter_map(|a| a.parse().ok()));
    (direct, out)
}

/// Candidats les plus proches de `user_identity` (XOR), hors Nœud
/// hébergeur, avec une adresse publiée ; au plus `max`.
pub async fn discover(
    dht: &DhtClient,
    user_identity: &[u8; 32],
    host_node: &[u8; 32],
    max: usize,
) -> Vec<Candidate> {
    let peers = dht
        .closest_peers(user_identity.to_vec())
        .await
        .unwrap_or_default();
    let ids: Vec<[u8; 32]> = peers.iter().filter_map(node_of_peer).collect();
    let mut all: Vec<[u8; 32]> = ids.iter().filter(|i| *i != host_node).copied().collect();
    all.sort_by_key(|id| xor_distance(id, user_identity));
    all.dedup();
    let mut out = Vec::new();
    for id in all {
        if out.len() >= max {
            break;
        }
        let (direct, addrs) = node_addrs(dht, &id).await;
        let Some(addr) = addrs.into_iter().next() else {
            continue;
        };
        let (ip, port) = direct.unwrap_or_default();
        out.push(Candidate {
            partner: Partner {
                node_id: id,
                ip,
                port,
            },
            addr,
        });
    }
    out
}

/// Dépose un bloc chiffré chez `c`.
pub async fn deposit_block(
    client: &BlockClient,
    c: &Candidate,
    id: &DepositIdentity,
    data: Vec<u8>,
) -> Result<(), ExchangeError> {
    let partner_peer = peer_of_node(&c.partner.node_id).ok_or(ExchangeError::NoPeerId)?;
    let signature = emergency_deposit_signature(
        &id.sig_priv_user,
        &id.keys.sig_pub,
        &client.peer_id().to_bytes(),
        &partner_peer.to_bytes(),
    );
    let hash = s3m_core::symmetric_suite::hash_sha256(&data);
    let req = Request {
        credential: Some(Credential::Emergency {
            sig_pub_user: id.sig_pub_user.to_vec(),
            vdf_y: id.proof.y.clone(),
            vdf_pi: id.proof.pi.clone(),
            emergency_pub: id.keys.sig_pub.to_vec(),
            signature,
        }),
        body: Body::EmergencyPut { data },
    };
    match client.request(c.addr.clone(), req).await? {
        Response::Stored(h) if h == hash.to_vec() => Ok(()),
        _ => Err(ExchangeError::Unexpected),
    }
}

/// Relit un bloc déposé sous `emergency_pub` (hash vérifié).
pub async fn fetch_block(
    client: &BlockClient,
    addr: Multiaddr,
    emergency_pub: &[u8; 32],
    hash: &BlockHash,
) -> Option<Vec<u8>> {
    let req = Request {
        credential: None,
        body: Body::EmergencyGet {
            emergency_pub: emergency_pub.to_vec(),
            hash: hash.to_vec(),
        },
    };
    match client.request(addr, req).await {
        Ok(Response::BlockData(d)) if s3m_core::symmetric_suite::hash_sha256(&d) == *hash => {
            Some(d)
        }
        _ => None,
    }
}

/// Libère `hashes` chez le partenaire `addr` ; `next_ts` : premier
/// horodatage à utiliser (strictement croissant), mis à jour. Rend le
/// nombre de blocs libérés.
pub async fn release_blocks(
    client: &BlockClient,
    addr: Multiaddr,
    keys: &EmergencyKeys,
    next_ts: &mut u64,
    hashes: &[BlockHash],
) -> Result<u64, ExchangeError> {
    let mut freed = 0;
    for chunk in hashes.chunks(MAX_RELEASE_HASHES) {
        let req = Request {
            credential: None,
            body: emergency_release(&keys.sig_priv, *next_ts, chunk),
        };
        *next_ts += 1;
        match client.request(addr.clone(), req).await? {
            Response::Ack { freed: n } => freed += n,
            _ => return Err(ExchangeError::Unexpected),
        }
    }
    Ok(freed)
}

/// Adresse d'un partenaire listé dans un manifeste (adresse notée, puis
/// entrée DHT).
pub async fn partner_addr(dht: Option<&DhtClient>, p: &Partner) -> Option<Multiaddr> {
    if let Some(a) = with_peer(&p.ip, p.port, &p.node_id).filter(|_| !p.ip.is_empty()) {
        return Some(a);
    }
    node_addrs(dht?, &p.node_id).await.1.into_iter().next()
}
