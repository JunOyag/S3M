//! K_node_self — confidentialité de la cartographie de dispersion du Nœud.
//! Id `crypto.k-node-self` (Phase 0). Réf. spec : docs/03-crypto/
//! k-node-self.md (§3.8). Symétrique de `k_self`, côté Nœud.
//!
//! ```text
//! K_node_self = KDF(priv_node, "node-recovery")
//! ```
//! Dérivée uniquement de la clé privée du Nœud — dérivable de la seed seule,
//! sans état local préservé (restauration complète possible, page spec,
//! §« Ce qu'elle protège »).
//!
//! `priv_node` : graine Ed25519 de 32 octets du Nœud (schéma de chemins
//! SLIP-0010, voir `crypto.identity-derivation` — la dérivation
//! seed → graine est hors périmètre de ce module).
//!
//! Invariants testés : déterminisme, sensibilité à `priv_node`, séparation
//! de domaine (le domaine `info` « node-recovery » est distinct de
//! « attachment-recovery » — les clés User et Nœud d'une même graine ne
//! collisionnent pas) — voir `tests/k_node_self_vectors.rs`.
//!
//! Spec V3 : `derive_k_node_self` = `KDF(priv_node, "node-recovery")` selon la convention unique
//! de crypto.symmetric-suite (`symmetric_suite::kdf`), sans sel ni entrée publique.

use crate::error::CoreError;
use crate::labels;
use crate::symmetric_suite::kdf;

/// `K_node_self = KDF(priv_node, "node-recovery")` — sortie 32 o.
pub fn derive_k_node_self(priv_node: &[u8; 32]) -> Result<[u8; 32], CoreError> {
    kdf(priv_node, labels::NODE_RECOVERY, &[], &[])
}

/// `K_node_snapshot = KDF(priv_node, "node-snapshot", sel, u32(index))` —
/// clé du bloc `index` du snapshot du NodeManifest
/// (`deploiement.disaster-recovery` § Snapshot), sel de 16 o neuf à chaque
/// émission.
pub fn derive_k_node_snapshot(
    priv_node: &[u8; 32],
    salt: &[u8; 16],
    index: u32,
) -> Result<[u8; 32], CoreError> {
    kdf(
        priv_node,
        labels::NODE_SNAPSHOT,
        salt,
        &[&index.to_be_bytes()],
    )
}
