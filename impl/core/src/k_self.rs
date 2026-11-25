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

/// `K_root = KDF(priv_user, "root-descriptor")` — sortie 32 o
/// (`crypto.k-self#k-root`).
pub fn derive_k_root(priv_user: &[u8; 32]) -> Result<[u8; 32], CoreError> {
    kdf(priv_user, labels::ROOT_DESCRIPTOR, &[], &[])
}

/// Version du format du descripteur scellé.
pub const ROOT_SEAL_VERSION: u8 = 1;

/// Descripteur scellé d'une racine : `0x01 ‖ nonce (12) ‖ AEAD(K_root,
/// nonce, aad = fs_root_hash, encryption_salt (16) ‖ key_version (2, BE))`,
/// 47 octets. Lié à `fs_root_hash` : détaché de sa racine, il ne s'ouvre pas.
pub fn seal_root_descriptor(
    priv_user: &[u8; 32],
    fs_root_hash: &[u8; 32],
    encryption_salt: &[u8; 16],
    key_version: u16,
    nonce: &[u8; 12],
) -> Result<Vec<u8>, CoreError> {
    let k = derive_k_root(priv_user)?;
    let mut clear = encryption_salt.to_vec();
    clear.extend_from_slice(&key_version.to_be_bytes());
    let sealed = crate::symmetric_suite::aead_seal(&k, nonce, fs_root_hash, &clear)?;
    let mut out = vec![ROOT_SEAL_VERSION];
    out.extend_from_slice(nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Ouvre le descripteur scellé de `fs_root_hash` : `(encryption_salt,
/// key_version)` ; `None` s'il est vide, d'une autre racine ou altéré.
pub fn open_root_descriptor(
    priv_user: &[u8; 32],
    fs_root_hash: &[u8; 32],
    seal: &[u8],
) -> Option<([u8; 16], u16)> {
    if seal.len() != 1 + 12 + 18 + 16 || seal[0] != ROOT_SEAL_VERSION {
        return None;
    }
    let k = derive_k_root(priv_user).ok()?;
    let clear = crate::symmetric_suite::aead_open(&k, &seal[1..13], fs_root_hash, &seal[13..]).ok()?;
    let salt: [u8; 16] = clear.get(..16)?.try_into().ok()?;
    let version = u16::from_be_bytes(clear.get(16..18)?.try_into().ok()?);
    Some((salt, version))
}
