//! Quota à la synchronisation multi-Connecteurs — id `protocols.quota-sync`,
//! partie `node` (Phase 4). Réf. spec : docs/04-protocols/quota-sync.md.
//! (Partie `connector` : `WriteQueue::paths_affected_by` dans
//! `impl/connector/src/write_queue.rs`.)
//!
//! Intégration des écritures de blocs reçues de **tous** les Connecteurs
//! d'un Utilisateur par timestamp croissant, tous appareils confondus,
//! jusqu'à saturation du quota (`node.UserQuota`) ; les suivantes sont
//! rejetées et renvoyées (liste de `block_hash`) à leur Connecteur d'origine.
//! La même règle s'applique à l'intégration de l'espace de secours.

use std::collections::BTreeMap;

/// Écriture de bloc en attente d'intégration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingWrite {
    pub timestamp: u64,
    /// Connecteur d'origine (identifiant de session ou d'appareil).
    pub connector: u32,
    pub block_hash: [u8; 32],
}

/// Résultat de l'intégration.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Integration {
    /// Blocs acceptés, dans l'ordre d'intégration.
    pub accepted: Vec<[u8; 32]>,
    /// Blocs rejetés, par Connecteur d'origine.
    pub rejected: BTreeMap<u32, Vec<[u8; 32]>>,
}

/// Intègre `writes` (toutes sources mêlées) dans la limite de `free_blocks`.
/// Ordre : timestamp croissant ; à égalité, ordre de réception (tri stable).
/// Un bloc déjà présent (même hash) ne consomme pas de quota.
pub fn integrate(
    mut writes: Vec<PendingWrite>,
    free_blocks: u64,
    already_stored: &dyn Fn(&[u8; 32]) -> bool,
) -> Integration {
    writes.sort_by_key(|w| w.timestamp);
    let mut out = Integration::default();
    let mut used = 0u64;
    for w in writes {
        if already_stored(&w.block_hash) || out.accepted.contains(&w.block_hash) {
            continue;
        }
        if used < free_blocks {
            used += 1;
            out.accepted.push(w.block_hash);
        } else {
            out.rejected
                .entry(w.connector)
                .or_default()
                .push(w.block_hash);
        }
    }
    out
}
