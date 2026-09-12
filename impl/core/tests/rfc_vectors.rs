//! Vecteurs de test de référence pour les primitives de bas niveau.
//! Réf. AGENTS.md / TECH_STACK.md : k_attach et keys sont jugés "suffisamment
//! simples pour un agent" À CONDITION d'être validés contre des vecteurs
//! externes, pas seulement contre la logique interne du crate.
//!
//! À compléter avant de marquer `crypto.keys` ou `crypto.k-attach` comme
//! `done` dans impl/status.yml :
//!   - RFC 8032 (Ed25519) : vecteurs de test §7.1
//!   - RFC 7748 (X25519)  : vecteurs de test §5.2
//!   - Vecteur croisé libsodium : crypto_sign_ed25519_sk_to_curve25519 sur au
//!     moins 3 clés connues, pour garantir l'interopérabilité avec un futur
//!     partenaire non-Rust sur le réseau (le protocole est censé être
//!     inter-implémentations).

#[test]
#[ignore = "Phase 0 — dépend de p2p_storage_core::keys::ed25519_priv_to_x25519"]
fn ed25519_to_x25519_matches_rfc7748_vectors() {
    todo!()
}

#[test]
#[ignore = "Phase 0 — les deux calculs (User et Node) doivent converger, cf. k_attach.rs"]
fn k_attach_is_symmetric_between_user_and_node() {
    todo!()
}
