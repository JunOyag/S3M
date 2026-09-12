//! K_self — auto-chiffrement de l'historique d'attachement côté User.
//! Réf. spec §3.8.
//!
//! ```text
//! K_self = KDF(priv_user, "attachment-recovery")
//! ```
//! Ne dépend d'aucune information externe (contrairement à K_attach) — permet
//! la reconstruction depuis la seed BIP-39 seule (§2.2, §7.1).

use crate::error::CoreError;

pub fn derive_k_self(_priv_user: &[u8; 32]) -> Result<[u8; 32], CoreError> {
    todo!("Phase 0 — HKDF(priv_user, info=\"attachment-recovery\")")
}
