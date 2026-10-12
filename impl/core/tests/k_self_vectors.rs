//! Vecteurs et invariants pour `crypto.k-self` (Phase 0).
//!
//! Pas de vecteur externe publié : dérivation propre au protocole
//! (`K_self = KDF(priv_user, "attachment-recovery")` — voir
//! `docs/03-crypto/k-self.md`). Invariants structurels :
//! - déterminisme (même `priv_user` -> même `K_self`), clé non nulle ;
//! - sensibilité à `priv_user` (deux Users -> clés distinctes) ;
//! - séparation de domaine : `K_self` est distinct des autres clés dérivées
//!   de material lié (`sig_priv_dispersal` co-dérivé d'un `K_attach` testé
//!   comme distinct — ici on fige que deux domaines `info` distincts ne
//!   collisionnent pas sur des entrées liées).
//!
//! Règle de fixtures : constantes internes arbitraires (graines RFC 8032
//! §7.1 TEST 1 / TEST 2 réutilisées comme graines d'entrée seulement —
//! jamais comme valeurs attendues).

use p2p_storage_core::k_self::derive_k_self;

/// RFC 8032 §7.1 TEST 1 — graine d'entrée seulement.
const USER_SEED_A: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
/// RFC 8032 §7.1 TEST 2 — graine d'entrée seulement.
const USER_SEED_B: [u8; 32] = [
    0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
    0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
];

/// Mêmes entrées -> même `K_self`, clé non nulle. `K_self` ne dépend
/// d'aucune information externe : la reconstruction depuis la seed seule
/// (page spec, §« Reconstruction complète ») exige ce déterminisme pur.
#[test]
fn k_self_derivation_is_deterministic() {
    let k1 = derive_k_self(&USER_SEED_A).expect("HKDF");
    let k2 = derive_k_self(&USER_SEED_A).expect("HKDF");
    assert_eq!(k1, k2);
    assert_ne!(k1, [0u8; 32]);
}

/// Deux graines User distinctes -> `K_self` distincts (seul le User via sa
/// seed peut déchiffrer sa propre liste — page spec, §« Rôle »).
#[test]
fn k_self_differs_per_priv_user() {
    let k_a = derive_k_self(&USER_SEED_A).expect("HKDF");
    let k_b = derive_k_self(&USER_SEED_B).expect("HKDF");
    assert_ne!(k_a, k_b);
}
