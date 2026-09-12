//! K_dispersal_content / K_dispersal_block — chiffrement des blocs internes
//! de l'arbre d'index (au-delà de la racine). Réf. spec §3.8, §3.6.
//!
//! ```text
//! K_dispersal_content = KDF(K_attach, "dispersal-content")
//! K_dispersal_block   = KDF(K_dispersal_content, block_hash)
//! ```
//! Propriété à tester explicitement (invariant de sécurité de la migration,
//! §3.7.1) : il ne doit PAS exister de chemin dans ce module permettant de
//! remonter de K_dispersal_content vers K_attach ou sig_priv_dispersal. Toute
//! fonction ajoutée ici qui prendrait K_dispersal_content en entrée pour
//! produire K_attach est un bug de conception — ajouter un test qui l'exclut
//! plutôt que de faire confiance à l'absence de code.

use crate::error::CoreError;

pub fn derive_k_dispersal_content(_k_attach: &[u8; 32]) -> Result<[u8; 32], CoreError> {
    todo!("Phase 0 — HKDF(k_attach, info=\"dispersal-content\")")
}

pub fn derive_k_dispersal_block(
    _k_dispersal_content: &[u8; 32],
    _block_hash: &[u8; 32],
) -> Result<[u8; 32], CoreError> {
    todo!("Phase 0 — HKDF(k_dispersal_content, info=block_hash)")
}
