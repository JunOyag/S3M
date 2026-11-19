//! K_dispersal_content / K_dispersal_block — id `crypto.k-dispersal` (Phase 0,
//! spec V3). Réf. spec : docs/03-crypto/k-dispersal.md (§3.8).
//!
//! ```text
//! K_dispersal_content = KDF(K_attach, "dispersal-content")
//! K_dispersal_block   = KDF(K_dispersal_content, "dispersal-block", sel_du_nœud)
//! ```
//! `sel_du_nœud` : 16 o CSPRNG, neuf à chaque émission d'un `IndexNode`,
//! porté par le `Stripe` parent (`encryption_salt`) ou, pour la racine, par
//! `DispersalRootPointer.dispersal_root_salt`. Une clé = un nœud = un
//! message ; indépendante de `block_hash`. `K_dispersal_content` ne permet
//! de reconstituer ni `K_attach` ni `sig_priv_dispersal` (sens unique).

use crate::error::CoreError;
use crate::labels;
use crate::symmetric_suite::kdf;

/// Taille du sel d'un `IndexNode` (spec V3).
pub const INDEX_NODE_SALT_LEN: usize = 16;

/// `K_dispersal_content = KDF(K_attach, "dispersal-content")`.
pub fn derive_k_dispersal_content(k_attach: &[u8; 32]) -> Result<[u8; 32], CoreError> {
    kdf(k_attach, labels::DISPERSAL_CONTENT, &[], &[])
}

/// `K_dispersal_block = KDF(K_dispersal_content, "dispersal-block", sel_du_nœud)`.
/// Un sel de longueur autre que 16 o est rejeté.
pub fn derive_k_dispersal_block(
    k_dispersal_content: &[u8; 32],
    index_node_salt: &[u8],
) -> Result<[u8; 32], CoreError> {
    if index_node_salt.len() != INDEX_NODE_SALT_LEN {
        return Err(CoreError::InvalidSaltLength {
            expected: INDEX_NODE_SALT_LEN,
            got: index_node_salt.len(),
        });
    }
    kdf(k_dispersal_content, labels::DISPERSAL_BLOCK, index_node_salt, &[])
}
