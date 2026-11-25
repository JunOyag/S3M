//! Publication de l'entrée DHT User — id `network.dht-directory` (partie
//! connector), et restauration de la racine depuis la DHT
//! (`deploiement.disaster-recovery`, partie connector). Réf. spec :
//! docs/01-network-dht/dht-directory.md, docs/07-deploiement/disaster-recovery.md.
//!
//! - Preuve VDF de `0x00 ‖ sig_pub_user` calculée une fois (fil dédié),
//!   conservée sur disque.
//! - Publication réactive : à chaque nouvelle racine validée par le Nœud
//!   (et au premier démarrage), horodatage strictement croissant.
//! - Nouvel appareil : la racine (hash, sel, version) est relue dans
//!   l'entrée User — la seule phrase de récupération suffit.

use std::path::Path;

use s3m_core::keys::derive_user_dht_key;
use s3m_core::vdf::{generate_identity_proof, VdfProof};
use s3m_protocol::entries::{
    decode_proof, encode_proof, open_user_entry, user_entry_envelope, user_identity, UserPlain,
};

use crate::dht_directory::DhtClient;

/// État de l'entrée User (dashboard).
#[derive(Debug, Clone, Default)]
pub struct UserEntryState {
    pub dht_connected: bool,
    pub proof_ready: bool,
    pub proof_error: Option<String>,
    pub published_root: Option<[u8; 32]>,
    pub published_at: Option<u64>,
    pub last_timestamp: u64,
    pub restored_from_dht: bool,
    pub last_error: Option<String>,
}

/// Preuve VDF de l'identité User, en cache ou calculée puis enregistrée.
pub async fn ensure_user_proof(
    cache: &Path,
    priv_user: &[u8; 32],
    pub_user: &[u8; 32],
) -> Result<VdfProof, String> {
    let identity = user_identity(priv_user, pub_user).map_err(|e| e.to_string())?;
    // Preuve en cache valable pour cette identité seulement (une rotation
    // d'identité en exige une nouvelle).
    let tag = cache.with_extension("id");
    let same = std::fs::read_to_string(&tag).map_or(true, |t| t.trim() == hex::encode(identity));
    if same {
        if let Some(p) = std::fs::read(cache).ok().and_then(|b| decode_proof(&b)) {
            let _ = std::fs::write(&tag, hex::encode(identity));
            return Ok(p);
        }
    }
    let proof = tokio::task::spawn_blocking(move || generate_identity_proof(&identity))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| format!("preuve VDF : {e}"))?;
    let tmp = cache.with_extension("tmp");
    std::fs::write(&tmp, encode_proof(&proof)).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, cache).map_err(|e| e.to_string())?;
    let _ = std::fs::write(&tag, hex::encode(identity));
    Ok(proof)
}

/// Entrée User publiée (vérifiée par le client DHT), déchiffrée.
pub async fn read_user_entry(
    client: &DhtClient,
    priv_user: &[u8; 32],
    pub_user: &[u8; 32],
) -> Option<UserPlain> {
    let key = derive_user_dht_key(priv_user, pub_user).ok()?;
    let env = client.get(key.to_vec()).await.ok()??;
    open_user_entry(priv_user, &env).ok()
}

/// Publie l'entrée User si la racine a changé depuis la dernière
/// publication (ou si rien n'a encore été publié).
pub async fn publish_if_changed(
    client: &DhtClient,
    priv_user: &[u8; 32],
    pub_user: &[u8; 32],
    proof: &VdfProof,
    plain: &UserPlain,
    state: &std::sync::Mutex<UserEntryState>,
    now: u64,
) {
    let ts = {
        let s = state.lock().unwrap();
        if s.published_root == Some(plain.fs_root_hash) && s.published_at.is_some() {
            return;
        }
        now.max(s.last_timestamp + 1)
    };
    // Espace local neuf (nouvel appareil, changement de Nœud) : ne jamais
    // remplacer une racine publiée par la racine vide, ce qui ferait perdre
    // la trace des fichiers aux autres appareils.
    if plain.fs_root_hash == [0u8; 32] {
        if let Some(cur) = read_user_entry(client, priv_user, pub_user).await {
            if cur.fs_root_hash != [0u8; 32] {
                state.lock().unwrap().last_error = Some(
                    "racine locale vide : entrée publiée conservée (fichiers d'un autre appareil)"
                        .into(),
                );
                return;
            }
        }
    }
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).expect("CSPRNG du système");
    let result = match user_entry_envelope(priv_user, pub_user, ts, proof, plain, &nonce) {
        Err(e) => Err(e.to_string()),
        Ok((key, env)) => client
            .put(key.to_vec(), env)
            .await
            .map_err(|e| e.to_string()),
    };
    let mut s = state.lock().unwrap();
    match result {
        Ok(()) => {
            s.published_root = Some(plain.fs_root_hash);
            s.published_at = Some(now);
            s.last_timestamp = ts;
            s.last_error = None;
        }
        Err(e) => s.last_error = Some(e),
    }
}
