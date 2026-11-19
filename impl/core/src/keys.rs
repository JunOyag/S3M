//! Conversion Ed25519 <-> X25519 pour l'id `crypto.k-attach` (Phase 0).
//! Réf. spec pilotée : docs/03-crypto/k-attach.md (§3.8, « K_attach —
//! métadonnées de dispersion ») — c'est la page qui porte la conversion
//! `ed25519_to_x25519` (manifest.yml); il n'existe aucune page « keys »
//! dédiée dans le plan documentaire.
//!
//! Convention de représentation (arbitrée) : `priv_user` / `priv_node` sont la
//! **graine Ed25519 de 32 octets** (première moitié de la clé secrète
//! seed||pk de libsodium). Le scalaire X25519 correspondant vaut
//! `clamp(SHA-512(graine)[0..32])`, exactement ce que calcule
//! `crypto_sign_ed25519_sk_to_curve25519` (libsodium) à partir de cette même
//! graine : h[0] &= 248 ; h[31] &= 127 ; h[31] |= 64.
//!
//! Rappel structurel (à ne pas casser) : `priv_user`/`pub_user` et
//! `priv_node`/`pub_node` sont des paires Ed25519 utilisées ailleurs pour la
//! signature. Les conversions X25519 ci-dessous ne doivent JAMAIS être
//! réutilisées pour signer quoi que ce soit — seulement pour l'échange
//! Diffie-Hellman menant à K_attach (le mélange de primitives est proscrit
//! sans cette conversion, cf. la note de la page k-attach).
//!
//! `derive_sig_priv_user` / `derive_user_dht_key` : dérivations DHT User
//! (network.dht-directory, spec V3).

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

use crate::error::CoreError;
use crate::labels;
use crate::symmetric_suite::kdf;

/// `ed25519_priv_to_x25519(graine)` — équivalent exact de
/// `crypto_sign_ed25519_sk_to_curve25519` (libsodium) pour une entrée de
/// 32 octets : `h = SHA-512(graine)`, clampage, sortie = `h[0..32]`.
pub fn ed25519_priv_to_x25519(ed25519_priv: &[u8; 32]) -> Result<[u8; 32], CoreError> {
    let mut h = [0u8; 64];
    h.copy_from_slice(&Sha512::digest(ed25519_priv));
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&h[..32]);
    h.zeroize();
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    Ok(scalar)
}

/// Symétrique côté clé publique — équivalent exact de
/// `crypto_sign_ed25519_pk_to_curve25519` (libsodium) : décompression
/// Edwards (encodage canonique exigé), rejet des points de petit ordre et de
/// toute composante de torsion (comme `ge25519_has_small_order` +
/// `ge25519_is_on_main_subgroup` côté libsodium), puis biration
/// `u = (1 + y) / (1 - y)` (RFC 7748 §6.1). Le bit de signe de l'encodage
/// Ed25519 est ignoré : `u` ne dépend que de `y`.
pub fn ed25519_pub_to_x25519(ed25519_pub: &[u8; 32]) -> Result<[u8; 32], CoreError> {
    let point: EdwardsPoint = CompressedEdwardsY(*ed25519_pub)
        .decompress()
        .ok_or(CoreError::KeyConversion)?;
    // `is_small_order` couvre aussi l'identité, que `is_torsion_free` pris
    // seul laisserait passer ([L]·identité = identité).
    if point.is_small_order() || !point.is_torsion_free() {
        return Err(CoreError::KeyConversion);
    }
    // Biration Edwards->Montgomery u = (1 + y) / (1 - y) (RFC 7748 §6.1) —
    // implémentée par curve25519-dalek (`to_montgomery`) ; le bit de signe
    // de l'encodage Ed25519 est ignoré : u ne dépend que de y.
    Ok(point.to_montgomery().to_bytes())
}

/// Graine de `sig_priv_user = KDF(priv_user, "dht-signing", —, pub_user)`
/// (spec V3, network.dht-directory § Signature sans exposer les identités) :
/// graine Ed25519 (RFC 8032) qui signe l'entrée DHT User sans exposer
/// `pub_user`.
pub fn derive_sig_priv_user(
    priv_user: &[u8; 32],
    pub_user: &[u8; 32],
) -> Result<[u8; 32], CoreError> {
    kdf(priv_user, labels::DHT_SIGNING, &[], &[pub_user])
}

/// Clé publique Ed25519 de la graine `sig_priv_user` — clé de vérification
/// de l'entrée User, publiée en clair et prouvée par la VDF
/// (`0x00 ‖ sig_pub_user`).
pub fn derive_sig_pub_user(sig_priv_user: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(sig_priv_user)
        .verifying_key()
        .to_bytes()
}

/// `user_dht_key = KDF(priv_user, "dht-lookup", —, pub_user)` — clé de
/// recherche de l'entrée User, calculable par le seul User.
pub fn derive_user_dht_key(
    priv_user: &[u8; 32],
    pub_user: &[u8; 32],
) -> Result<[u8; 32], CoreError> {
    kdf(priv_user, labels::DHT_LOOKUP, &[], &[pub_user])
}
