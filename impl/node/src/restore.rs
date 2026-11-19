//! Restauration (disaster recovery) — id `deploiement.disaster-recovery`,
//! partie `node` (Phase 6). Réf. spec :
//! docs/07-deploiement/disaster-recovery.md. (Partie `connector` : étapes 5
//! et 6 = `network.bootstrap` + `crypto.master-key-chain`.)
//!
//! Depuis la seule seed « Node » :
//! 1. identité Nœud (`crypto.identity-derivation`) ;
//! 2. entrée DHT Node → `NodeSnapshotPointer` déchiffré sous `K_node_self` :
//!    racine et partenaires du snapshot du NodeManifest ;
//! 3. (récupération de k fragments sur N du snapshot : protocole d'échange) ;
//! 4. pour chaque Utilisateur rattaché : `K_attach` recalculé (symétrique)
//!    et clé DHT de son DispersalManifest, puis reconstruction des k blocs
//!    de chaque stripe depuis la parité (`migration::rebuild_stripe`).

use p2p_storage_core::k_attach::derive_k_attach_as_node;
use p2p_storage_core::k_node_self::derive_k_node_self;
use p2p_storage_core::CoreError;
use p2p_storage_protocol::dht::{dispersal_dht_key, open_blob, DhtError, EntryKind};
use p2p_storage_protocol::fb::dht as fb;

/// Erreurs de restauration.
#[derive(Debug, thiserror::Error)]
pub enum RestoreError {
    #[error(transparent)]
    Core(#[from] CoreError),
    #[error(transparent)]
    Dht(#[from] DhtError),
    #[error("entrée Node mal formée : {0}")]
    Format(&'static str),
}

/// Point d'entrée du snapshot du NodeManifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotPointer {
    pub root_hash: Vec<u8>,
    /// `(partner_id, node_id)` des partenaires du stripe racine.
    pub partners: Vec<(u16, Vec<u8>)>,
}

/// Étape 2 : déchiffre le pointeur de snapshot de l'entrée Node (enveloppe
/// déjà vérifiée par l'adaptateur DHT).
pub fn snapshot_pointer(
    priv_node: &[u8; 32],
    node_envelope: &[u8],
) -> Result<SnapshotPointer, RestoreError> {
    let env = flatbuffers::root::<fb::DhtEnvelope>(node_envelope)
        .map_err(|_| RestoreError::Format("DhtEnvelope"))?;
    let payload = env
        .payload()
        .ok_or(RestoreError::Format("payload"))?
        .bytes();
    let entry = fb::root_as_node_entry(payload).map_err(|_| RestoreError::Format("NodeEntry"))?;
    let blob = entry
        .snapshot_ciphertext()
        .ok_or(RestoreError::Format("snapshot_ciphertext"))?;
    let clear = open_blob(
        &derive_k_node_self(priv_node)?,
        EntryKind::Node.blob_aad_label(),
        blob.bytes(),
    )?;
    let p = flatbuffers::root::<fb::NodeSnapshotPointer>(&clear)
        .map_err(|_| RestoreError::Format("NodeSnapshotPointer"))?;
    Ok(SnapshotPointer {
        root_hash: p
            .node_snapshot_root_hash()
            .map(|v| v.bytes().to_vec())
            .unwrap_or_default(),
        partners: p
            .node_snapshot_root_partners()
            .map(|v| {
                v.iter()
                    .map(|x| {
                        (
                            x.partner_id(),
                            x.node_id().map(|b| b.bytes().to_vec()).unwrap_or_default(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default(),
    })
}

/// Étape 4 : pour un Utilisateur rattaché `(pub_user, salt)` restauré du
/// NodeManifest, `K_attach` et la clé DHT de son DispersalManifest.
pub fn attached_user_keys(
    priv_node: &[u8; 32],
    pub_user: &[u8; 32],
    salt: &[u8],
) -> Result<([u8; 32], [u8; 32]), CoreError> {
    let k_attach = derive_k_attach_as_node(priv_node, pub_user, salt)?;
    Ok((k_attach, dispersal_dht_key(&k_attach)))
}
