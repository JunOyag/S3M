//! K_attach — clé partagée Nœud <-> Connecteur pour un couple (User, Node).
//! Réf. spec §3.8. NE chiffre JAMAIS le contenu réel des blocs (c'est le rôle
//! de `k_block`) — uniquement le `DispersalManifest`.
//!
//! ```text
//! priv_user_x25519 = ed25519_to_x25519(priv_user)
//! pub_node_x25519  = ed25519_to_x25519(pub_node)
//! K_attach = KDF(X25519(priv_user_x25519, pub_node_x25519), salt)
//! ```
//! Côté Nœud, calcul symétrique avec (priv_node_x25519, pub_user_x25519).
//! Invariant à tester : les deux calculs doivent produire le même résultat
//! (propriété d'échange X25519) — test à écrire avant l'implémentation.

use crate::error::CoreError;

pub fn derive_k_attach_as_user(
    _priv_user: &[u8; 32],
    _pub_node: &[u8; 32],
    _salt: &[u8],
) -> Result<[u8; 32], CoreError> {
    todo!("Phase 0 — X25519(ed25519_to_x25519(priv_user), ed25519_to_x25519(pub_node)) puis KDF(_, salt)")
}

pub fn derive_k_attach_as_node(
    _priv_node: &[u8; 32],
    _pub_user: &[u8; 32],
    _salt: &[u8],
) -> Result<[u8; 32], CoreError> {
    todo!("Phase 0 — calcul symétrique, doit être identique à derive_k_attach_as_user pour le même salt")
}

/// `sig_priv_dispersal = KDF(K_attach, "dispersal-signing")` — §3.9.
/// Calculable par le Nœud ET le Connecteur, mais seul le Nœud doit s'en
/// servir pour signer en fonctionnement normal (règle applicative, pas
/// cryptographique — rien n'empêche techniquement le Connecteur de signer,
/// c'est une invariant à faire respecter côté impl/connector, pas ici).
pub fn derive_sig_priv_dispersal(_k_attach: &[u8; 32]) -> Result<[u8; 32], CoreError> {
    todo!("Phase 0 — HKDF(k_attach, info=\"dispersal-signing\")")
}
