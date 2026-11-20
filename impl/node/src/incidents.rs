//! Incidents et compromissions — id `securite.incidents-compromissions`,
//! partie `node` (Phase 5). Réf. spec :
//! docs/05-securite/incidents-compromissions.md.
//!
//! Compromission de `priv_node` (seed intacte) ou perte matérielle :
//! - identité suivante dérivée de la **même seed** à l'index `+1`, avec sa
//!   clé de secours miroir (`…/1'/<i+1>'`, `…/2'/<i+1>'`) ;
//! - `migration_pointer` signé par l'**ancienne** clé de secours
//!   `priv_node_recovery` sur `L("s3m/sig/migration-pointer/v1") ‖
//!   payload`, publié dans l'entrée Node de l'ancien `node_id`
//!   (vérification et suivi : `protocol::dht::verify_migration_pointer`,
//!   `connector::bootstrap::resolve`).
//! - Limite fondamentale : si la seed fuit, la clé de secours aussi.

use flatbuffers::FlatBufferBuilder;
use s3m_core::identity_derivation::{derive_identity_seed, IdentityRole};
use s3m_core::CoreError;
use s3m_protocol::dht::{sign, SIG_LABEL_MIGRATION_POINTER};
use s3m_protocol::fb::dht as fb;

/// Graines Ed25519 d'une identité Nœud et de sa clé de secours miroir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeIdentity {
    pub index: u32,
    pub node_seed: [u8; 32],
    pub recovery_seed: [u8; 32],
}

/// Identité Nœud d'index `index` (et sa clé de secours au même index).
pub fn node_identity(bip39_seed: &[u8; 64], index: u32) -> Result<NodeIdentity, CoreError> {
    Ok(NodeIdentity {
        index,
        node_seed: derive_identity_seed(bip39_seed, IdentityRole::Node, index)?,
        recovery_seed: derive_identity_seed(bip39_seed, IdentityRole::NodeRecovery, index)?,
    })
}

/// Construit le `SignedMigrationPointer` (octets FlatBuffers) à publier dans
/// l'entrée Node de l'ancien `node_id`.
pub fn sign_migration_pointer(
    old_recovery_seed: &[u8; 32],
    old_node_id: &[u8; 32],
    new_node_id: &[u8; 32],
    seq: u64,
    timestamp: u64,
) -> Vec<u8> {
    let mut inner = FlatBufferBuilder::new();
    let o = inner.create_vector(old_node_id);
    let n = inner.create_vector(new_node_id);
    let p = fb::MigrationPointerPayload::create(
        &mut inner,
        &fb::MigrationPointerPayloadArgs {
            old_node_id: Some(o),
            new_node_id: Some(n),
            seq,
            timestamp,
        },
    );
    inner.finish_minimal(p);
    let payload = inner.finished_data().to_vec();
    let sig = sign(old_recovery_seed, SIG_LABEL_MIGRATION_POINTER, &payload);
    let mut fbb = FlatBufferBuilder::new();
    let pv = fbb.create_vector(&payload);
    let sv = fbb.create_vector(&sig);
    let smp = fb::SignedMigrationPointer::create(
        &mut fbb,
        &fb::SignedMigrationPointerArgs {
            payload: Some(pv),
            signature: Some(sv),
        },
    );
    fbb.finish_minimal(smp);
    fbb.finished_data().to_vec()
}
