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
//! Choix d'implémentation du « KDF » de la spec : HKDF-SHA-256 (bibliothèque
//! `hkdf`, cf. impl/TECH_STACK.md et `k_attach.rs`), sortie 32 octets,
//! `info = "attachment-recovery"`, salt HKDF interne par défaut (aucun salt
//! externe nommé par la formule — même cas que `sig_priv_dispersal`).
//!
//! `priv_user` : graine Ed25519 de 32 octets (schéma de chemins SLIP-0010,
//! voir `crypto.identity-derivation` — la dérivation seed → graine est hors
//! périmètre de ce module, qui prend la graine en entrée).
//!
//! Invariants testés : déterminisme, sensibilité à `priv_user`, séparation
//! de domaine (distinct de `K_attach`-dérivés pour des entrées liées) — voir
//! `tests/k_self_vectors.rs`.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::CoreError;

/// Dérive `K_self` depuis la graine Ed25519 du User.
///
/// Chiffre, dans l'entrée DHT publique du User, la liste complète des tuples
/// d'attachement — seul le User (via sa seed) peut la déchiffrer (page spec,
/// §« Rôle »).
pub fn derive_k_self(priv_user: &[u8; 32]) -> Result<[u8; 32], CoreError> {
    let mut okm = [0u8; 32];
    Hkdf::<Sha256>::new(None, priv_user)
        .expand(b"attachment-recovery", &mut okm)
        .map_err(|_| CoreError::KdfFailure)?;
    Ok(okm)
}
