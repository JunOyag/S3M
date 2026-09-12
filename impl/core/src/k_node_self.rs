//! K_node_self — confidentialité de la cartographie de dispersion du Nœud.
//! Réf. spec §3.8. Symétrique de k_self, côté Nœud.
//!
//! ```text
//! K_node_self = KDF(priv_node, "node-recovery")
//! ```

use crate::error::CoreError;

pub fn derive_k_node_self(_priv_node: &[u8; 32]) -> Result<[u8; 32], CoreError> {
    todo!("Phase 0 — HKDF(priv_node, info=\"node-recovery\")")
}
