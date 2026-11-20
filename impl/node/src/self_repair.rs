//! Intégrité des blocs locaux et auto-réparation — id
//! `securite.integrite-autoreparation`, partie `node` (Phase 5). Réf. spec :
//! docs/05-securite/integrite-autoreparation.md. (Partie `connector` :
//! `IntegrityLog::repairs` dans `impl/connector/src/integrity.rs`.)
//!
//! - **Auto-réparation** : le Nœud remplace sa copie corrompue par le bloc
//!   reconstruit que lui renvoie le Connecteur — simple exécutant, mais il
//!   vérifie que le bloc reçu correspond bien au `block_hash` avant d'écrire.
//! - **Scrubbing proactif** : recalcul périodique des hash de la copie
//!   locale, comparés aux `block_hash` du DispersalManifest ; des anomalies
//!   répétées sur un même volume (seuil retenu : 3) signalent une défaillance
//!   matérielle au dashboard.

use std::collections::BTreeMap;

use s3m_core::symmetric_suite::hash_sha256;

use crate::{Owner, PhysicalStore, StorageError};

/// Seuil d'anomalies par volume au-delà duquel le volume est signalé.
pub const FAILING_VOLUME_THRESHOLD: usize = 3;

/// Erreurs de réparation.
#[derive(Debug, thiserror::Error)]
pub enum RepairError {
    #[error("le bloc reçu ne correspond pas au block_hash : réparation refusée")]
    HashMismatch,
    #[error(transparent)]
    Storage(#[from] StorageError),
}

/// Applique une réparation envoyée par le Connecteur.
pub fn apply_repair(
    store: &mut PhysicalStore,
    owner: &Owner,
    block_hash: &[u8; 32],
    block: &[u8],
) -> Result<(), RepairError> {
    if &hash_sha256(block) != block_hash {
        return Err(RepairError::HashMismatch);
    }
    store.write_block(owner, block_hash, block)?;
    Ok(())
}

/// Rapport de scrubbing.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ScrubReport {
    pub checked: usize,
    pub corrupted: Vec<[u8; 32]>,
    /// Volumes à signaler (défaillance matérielle probable).
    pub failing_volumes: Vec<u32>,
}

/// Scrubbing : `blocks` = `(block_hash attendu, volume)` ; `read` relit le
/// bloc local. Un bloc absent ou dont le hash diffère est compté corrompu.
pub fn scrub(
    blocks: &[([u8; 32], u32)],
    read: &dyn Fn(&[u8; 32]) -> Option<Vec<u8>>,
) -> ScrubReport {
    let mut report = ScrubReport::default();
    let mut per_volume: BTreeMap<u32, usize> = BTreeMap::new();
    for (hash, volume) in blocks {
        report.checked += 1;
        let ok = read(hash).is_some_and(|b| &hash_sha256(&b) == hash);
        if !ok {
            report.corrupted.push(*hash);
            *per_volume.entry(*volume).or_insert(0) += 1;
        }
    }
    report.failing_volumes = per_volume
        .into_iter()
        .filter(|(_, n)| *n >= FAILING_VOLUME_THRESHOLD)
        .map(|(v, _)| v)
        .collect();
    report
}
