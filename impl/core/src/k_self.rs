//! K_self — auto-chiffrement de l'historique d'attachement côté User.
//! Id `crypto.k-self` (Phase 0). Réf. spec : docs/03-crypto/k-self.md
//! (§3.8).
//!
//! ```text
//! K_self = KDF(priv_user, "attachment-recovery")
//! ```
//! Ne dépend d'aucune information externe (contrairement à K_attach) — permet
//! la reconstruction depuis la seed BIP-39 seule (§2.2, §7.1 : identité User
//! → entrée DHT → déchiffrement de la liste d'attachements → K_attach).
//!
//! `priv_user` : graine Ed25519 de 32 octets (schéma de chemins SLIP-0010,
//! voir `crypto.identity-derivation` — la dérivation seed → graine est hors
//! périmètre de ce module, qui prend la graine en entrée).
//!
//! Invariants testés : déterminisme, sensibilité à `priv_user`, séparation
//! de domaine (distinct de `K_attach`-dérivés pour des entrées liées) — voir
//! `tests/k_self_vectors.rs`.
//!
//! Spec V3 : `derive_k_self` = `KDF(priv_user, "attachment-recovery")` selon la convention unique
//! de crypto.symmetric-suite (`symmetric_suite::kdf`), sans sel ni entrée publique.

use crate::error::CoreError;
use crate::labels;
use crate::symmetric_suite::kdf;

/// `K_self = KDF(priv_user, "attachment-recovery")` — sortie 32 o.
pub fn derive_k_self(priv_user: &[u8; 32]) -> Result<[u8; 32], CoreError> {
    kdf(priv_user, labels::ATTACHMENT_RECOVERY, &[], &[])
}
