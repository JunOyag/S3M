//! Publication de l'entrée DHT Node — id `network.dht-directory` (partie
//! node). Réf. spec : docs/01-network-dht/dht-directory.md.
//!
//! La preuve VDF de l'identité `0x00 ‖ pub_node` est calculée une seule
//! fois dans un fil dédié (≈ 30 s à 1,5 min) puis conservée sur disque ;
//! l'entrée est publiée dès qu'elle est prête, puis republiée à l'échéance
//! lissée (`next_republish_at(pub_node, …)`) ou si l'adresse change.
//! Le `NodeSnapshotPointer` (snapshot du NodeManifest, `snapshot_engine`)
//! est chiffré sous `K_node_self` ; tout nouveau pointeur republie l'entrée.

use std::path::Path;

use s3m_core::vdf::{generate_identity_proof, VdfProof};
use s3m_protocol::dht::next_republish_at;
use s3m_protocol::entries::{
    decode_proof, encode_proof, node_entry_envelope, node_identity, NodeEntryParams,
};

use crate::dht_directory::DhtNode;

/// État de l'entrée Node (dashboard).
#[derive(Debug, Clone, Default)]
pub struct NodeEntryState {
    pub proof_ready: bool,
    pub proof_error: Option<String>,
    pub published_at: Option<u64>,
    pub next_republish: u64,
    pub published_addr: Option<(String, u16)>,
    /// Multiaddrs publiées (`network.traversee-nat`).
    pub published_addrs: Vec<String>,
    pub published_snapshot: Option<Vec<u8>>,
    /// Dernière enveloppe publiée (jointe aux propositions de partenariat).
    pub last_envelope: Option<Vec<u8>>,
    pub last_error: Option<String>,
    /// Clé d'annonce à publier (`protocols.canal-noeud`) et celle publiée.
    pub announce: Option<[u8; 32]>,
    pub published_announce: Option<[u8; 32]>,
}

/// Preuve VDF en cache, ou calculée (bloquant, dans un fil dédié) puis
/// enregistrée.
pub async fn ensure_proof(cache: &Path, identity: [u8; 33]) -> Result<VdfProof, String> {
    if let Some(p) = std::fs::read(cache).ok().and_then(|b| decode_proof(&b)) {
        return Ok(p);
    }
    let proof = tokio::task::spawn_blocking(move || generate_identity_proof(&identity))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| format!("preuve VDF : {e}"))?;
    let tmp = cache.with_extension("tmp");
    std::fs::write(&tmp, encode_proof(&proof)).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, cache).map_err(|e| e.to_string())?;
    Ok(proof)
}

/// Preuve de l'identité Node.
pub async fn ensure_node_proof(cache: &Path, pub_node: &[u8; 32]) -> Result<VdfProof, String> {
    ensure_proof(cache, node_identity(pub_node).map_err(|e| e.to_string())?).await
}

/// Publie l'entrée Node si elle est due ; met `state` à jour.
#[allow(clippy::too_many_arguments)]
pub async fn publish_if_due(
    dht: &DhtNode,
    priv_node: &[u8; 32],
    pub_node: &[u8; 32],
    pub_node_recovery: &[u8; 32],
    addr: (String, u16),
    proof: &VdfProof,
    snapshot: Option<Vec<u8>>,
    state: &std::sync::Mutex<NodeEntryState>,
    now: u64,
) {
    publish_entry(
        dht,
        priv_node,
        pub_node,
        pub_node_recovery,
        Some(addr),
        Vec::new(),
        proof,
        snapshot,
        state,
        now,
    )
    .await
}

/// Comme [`publish_if_due`], avec l'adresse directe facultative (Nœud
/// derrière un NAT) et la liste des multiaddrs joignables.
#[allow(clippy::too_many_arguments)]
pub async fn publish_entry(
    dht: &DhtNode,
    priv_node: &[u8; 32],
    pub_node: &[u8; 32],
    pub_node_recovery: &[u8; 32],
    direct: Option<(String, u16)>,
    addrs: Vec<String>,
    proof: &VdfProof,
    snapshot: Option<Vec<u8>>,
    state: &std::sync::Mutex<NodeEntryState>,
    now: u64,
) {
    let addr = direct.unwrap_or_default();
    let due = {
        let s = state.lock().unwrap();
        s.published_at.is_none()
            || now >= s.next_republish
            || s.published_addr.as_ref() != Some(&addr)
            || s.published_addrs != addrs
            || s.published_snapshot != snapshot
            || s.published_announce != s.announce
    };
    let announce = state.lock().unwrap().announce;
    if !due {
        return;
    }
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).expect("CSPRNG du système");
    let env = node_entry_envelope(
        priv_node,
        &NodeEntryParams {
            ip: &addr.0,
            port: addr.1,
            timestamp: now,
            proof,
            pub_node_recovery,
            snapshot_pointer: snapshot.as_deref(),
            addrs: &addrs,
            pub_node_announce: announce.as_ref(),
        },
        &nonce,
    );
    let result = match env {
        Err(e) => Err(e.to_string()),
        Ok(env) => dht
            .put(pub_node.to_vec(), env.clone())
            .await
            .map(|_| env)
            .map_err(|e| e.to_string()),
    };
    let mut s = state.lock().unwrap();
    match result {
        Ok(env) => {
            s.last_envelope = Some(env);
            s.published_at = Some(now);
            s.next_republish = next_republish_at(pub_node, now + 1);
            s.published_addr = Some(addr);
            s.published_addrs = addrs;
            s.published_snapshot = snapshot;
            s.published_announce = announce;
            s.last_error = None;
        }
        Err(e) => s.last_error = Some(e),
    }
}
