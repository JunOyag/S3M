//! K_attach — clé partagée Nœud <-> Connecteur pour un couple (User, Node).
//! Id `crypto.k-attach` (Phase 0). Réf. spec : docs/03-crypto/k-attach.md
//! (§3.8). NE chiffre JAMAIS le contenu réel des blocs (c'est le rôle de
//! `k_block`) — uniquement le `DispersalManifest`.
//!
//! ```text
//! priv_user_x25519 = ed25519_to_x25519(priv_user)
//! pub_node_x25519  = ed25519_to_x25519(pub_node)
//! K_attach = KDF(X25519(priv_user_x25519, pub_node_x25519), "attach", salt)
//! ```
//! Côté Nœud, calcul symétrique avec (priv_node_x25519, pub_user_x25519).
//! Invariant testé : les deux calculs produisent le même résultat
//! (propriété d'échange X25519) — voir `tests/rfc_vectors.rs`.
//!
//! KDF : convention unique de crypto.symmetric-suite (`symmetric_suite::kdf`),
//! étiquette "attach" (spec V3 ; la V2 utilisait un `info` vide).
//!
//! `priv_user` / `priv_node` : graine Ed25519 de 32 octets (voir `keys.rs`).

use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::CoreError;
use crate::keys::{ed25519_priv_to_x25519, ed25519_pub_to_x25519};
use crate::labels;
use crate::symmetric_suite::kdf;

/// `K_attach = KDF(secret_partagé_X25519, "attach", salt)` (spec V3,
/// convention KDF de crypto.symmetric-suite) — à partir du secret DH déjà
/// calculé. Le sel est fixé par le Connecteur à l'attachement.
pub fn derive_k_attach_from_shared_secret(
    shared_secret: &[u8; 32],
    salt: &[u8],
) -> Result<[u8; 32], CoreError> {
    kdf(shared_secret, labels::ATTACH, salt, &[])
}

/// Côté User : `X25519(ed25519_to_x25519(priv_user), ed25519_to_x25519(pub_node))`
/// puis [`derive_k_attach_from_shared_secret`].
pub fn derive_k_attach_as_user(
    priv_user: &[u8; 32],
    pub_node: &[u8; 32],
    salt: &[u8],
) -> Result<[u8; 32], CoreError> {
    dh_then_kdf(priv_user, pub_node, salt)
}

/// Côté Nœud : calcul symétrique avec ses propres clés — même `K_attach`.
pub fn derive_k_attach_as_node(
    priv_node: &[u8; 32],
    pub_user: &[u8; 32],
    salt: &[u8],
) -> Result<[u8; 32], CoreError> {
    dh_then_kdf(priv_node, pub_user, salt)
}

fn dh_then_kdf(
    own_priv: &[u8; 32],
    peer_pub: &[u8; 32],
    salt: &[u8],
) -> Result<[u8; 32], CoreError> {
    let priv_x = ed25519_priv_to_x25519(own_priv)?;
    let pub_x = ed25519_pub_to_x25519(peer_pub)?;
    let shared = StaticSecret::from(priv_x).diffie_hellman(&PublicKey::from(pub_x));
    derive_k_attach_from_shared_secret(shared.as_bytes(), salt)
}

/// Graine de `sig_priv_dispersal = KDF(K_attach, "dispersal-signing")`.
pub fn derive_sig_priv_dispersal(k_attach: &[u8; 32]) -> Result<[u8; 32], CoreError> {
    kdf(k_attach, labels::DISPERSAL_SIGNING, &[], &[])
}
