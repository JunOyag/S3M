//! Conversion Ed25519 <-> X25519 et dérivation des clés de signature dédiées.
//! Réf. spec : §3.8 "K_attach — métadonnées de dispersion", §3.9 "Signature
//! sans exposer pub_user". Doc pilotée : docs/03-crypto/keys.md (à créer si
//! absente — voir manifest.yml).
//!
//! Rappel structurel (à ne pas casser) : `priv_user`/`pub_user` et
//! `priv_node`/`pub_node` sont des paires Ed25519 utilisées ailleurs pour la
//! signature. Les conversions X25519 ci-dessous ne doivent JAMAIS être
//! réutilisées pour signer quoi que ce soit — seulement pour l'échange
//! Diffie-Hellman menant à K_attach (mélange de primitives proscrit par la
//! spec).

use crate::error::CoreError;

/// `ed25519_to_x25519(priv_key)` — application birationnelle standard
/// (équivalent `crypto_sign_ed25519_sk_to_curve25519` de libsodium).
pub fn ed25519_priv_to_x25519(_ed25519_priv: &[u8; 32]) -> Result<[u8; 32], CoreError> {
    todo!("Phase 0 — convertir la clé privée Ed25519 en scalaire X25519")
}

/// Symétrique côté clé publique (`crypto_sign_ed25519_pk_to_curve25519`).
pub fn ed25519_pub_to_x25519(_ed25519_pub: &[u8; 32]) -> Result<[u8; 32], CoreError> {
    todo!("Phase 0 — convertir la clé publique Ed25519 en point X25519")
}

/// `sig_priv_user = KDF(priv_user, pub_user, "dht-signing")` — §3.9.
/// Permet de signer l'entrée DHT User sans jamais exposer `pub_user`.
pub fn derive_sig_priv_user(
    _priv_user: &[u8; 32],
    _pub_user: &[u8; 32],
) -> Result<[u8; 32], CoreError> {
    todo!("Phase 0 — HKDF(priv_user || pub_user, info=\"dht-signing\")")
}
