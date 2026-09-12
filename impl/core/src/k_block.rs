//! K_block — chiffrement du contenu réel des blocs de données/parité.
//! Réf. spec §3.8. JAMAIS dérivée ni détenue par le Nœud — uniquement par le
//! Connecteur, depuis la seed BIP-39 du User.
//!
//! ```text
//! K_block = KDF(master_key[version], block_hash, encryption_salt)
//! ```
//! `master_key[version]` provient de `master_key_chain.rs` (résolution de
//! version). `encryption_salt` est porté par l'entrée FS (`DirectoryEntry`,
//! §3.13), pas par ce module — appelant à charge de le fournir.

use crate::error::CoreError;

pub fn derive_k_block(
    _master_key_version: &[u8; 32],
    _block_hash: &[u8; 32],
    _encryption_salt: &[u8],
) -> Result<[u8; 32], CoreError> {
    todo!("Phase 0 — HKDF(master_key[version], salt=encryption_salt, info=block_hash) — vérifier l'ordre exact salt/info avant impl, cf. docs/03-crypto/k-block.md")
}
