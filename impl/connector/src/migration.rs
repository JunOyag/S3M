//! Migration vers un nouveau Nœud — id `protocols.migration-noeud`, partie
//! `connector` (Phase 4). Réf. spec : docs/04-protocols/migration-noeud.md.
//!
//! Le Connecteur **seul** re-dérive l'ancien `K_attach`, s'en sert
//! uniquement pour déchiffrer l'ancienne entrée DHT `DispersalManifest`, et
//! transmet au nouveau Nœud un [`Handoff`] : `dispersal_root_hash`,
//! `dispersal_root_partners` (+ `dispersal_root_salt`, V3) et
//! `K_dispersal_content` — **jamais** l'ancien `K_attach` ni
//! `sig_priv_dispersal`. Aucune coopération de l'ancien Nœud n'est requise.

use s3m_core::k_attach::derive_k_attach_as_user;
use s3m_core::k_dispersal::derive_k_dispersal_content;
use s3m_protocol::dht::{open_blob, DhtError, EntryKind};
use s3m_protocol::fb::dht as fb;

/// Ce que reçoit le nouveau Nœud. Par construction, aucun champ ne permet
/// de signer sur l'ancienne entrée DHT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handoff {
    pub dispersal_root_hash: Vec<u8>,
    /// `DispersalRootPointer.dispersal_root_partners`, sérialisés tels quels
    /// (table `dispersal.Partner`) : `(partner_id, node_id, ip, port)`.
    pub root_partners: Vec<(u16, Vec<u8>, String, u16)>,
    pub dispersal_root_salt: Vec<u8>,
    pub k_dispersal_content: [u8; 32],
}

/// Erreurs de préparation.
#[derive(Debug, thiserror::Error)]
pub enum MigrationError {
    #[error(transparent)]
    Core(#[from] s3m_core::CoreError),
    #[error(transparent)]
    Dht(#[from] DhtError),
    #[error("entrée DispersalManifest mal formée : {0}")]
    Format(&'static str),
}

/// Prépare le transfert à partir de l'ancienne entrée DHT (enveloppe déjà
/// vérifiée par le client DHT) et de l'ancien attachement `(pub_node, salt)`.
pub fn prepare_handoff(
    priv_user: &[u8; 32],
    old_pub_node: &[u8; 32],
    old_salt: &[u8],
    old_dispersal_envelope: &[u8],
) -> Result<Handoff, MigrationError> {
    let k_attach = derive_k_attach_as_user(priv_user, old_pub_node, old_salt)?;
    let env = flatbuffers::root::<fb::DhtEnvelope>(old_dispersal_envelope)
        .map_err(|_| MigrationError::Format("DhtEnvelope"))?;
    let payload = env
        .payload()
        .ok_or(MigrationError::Format("payload"))?
        .bytes();
    let entry = fb::root_as_dispersal_entry(payload)
        .map_err(|_| MigrationError::Format("DispersalEntry"))?;
    let blob = entry
        .ciphertext()
        .ok_or(MigrationError::Format("ciphertext"))?;
    let clear = open_blob(
        &k_attach,
        EntryKind::Dispersal.blob_aad_label(),
        blob.bytes(),
    )?;
    let ptr = flatbuffers::root::<fb::DispersalRootPointer>(&clear)
        .map_err(|_| MigrationError::Format("DispersalRootPointer"))?;
    let root_partners = ptr
        .dispersal_root_partners()
        .map(|v| {
            v.iter()
                .map(|p| {
                    (
                        p.partner_id(),
                        p.node_id().map(|b| b.bytes().to_vec()).unwrap_or_default(),
                        p.ip().unwrap_or_default().to_owned(),
                        p.port(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(Handoff {
        dispersal_root_hash: ptr
            .dispersal_root_hash()
            .map(|v| v.bytes().to_vec())
            .unwrap_or_default(),
        root_partners,
        dispersal_root_salt: ptr
            .dispersal_root_salt()
            .map(|v| v.bytes().to_vec())
            .unwrap_or_default(),
        k_dispersal_content: derive_k_dispersal_content(&k_attach)?,
    })
}
