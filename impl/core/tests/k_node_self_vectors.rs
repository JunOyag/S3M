//! Vecteurs et invariants pour `crypto.k-node-self` (Phase 0).
//!
//! Pas de vecteur externe publié : dérivation propre au protocole
//! (`K_node_self = KDF(priv_node, "node-recovery")` — voir
//! `docs/03-crypto/k-node-self.md`). Invariants structurels :
//! - déterminisme (même `priv_node` -> même clé), clé non nulle ;
//! - sensibilité à `priv_node` (deux Nœuds -> clés distinctes) ;
//! - séparation de domaine avec `K_self` : une même graine dérivée sous les
//!   deux domaines `info` (« node-recovery » vs « attachment-recovery »)
//!   ne collisionne jamais — un Nœud et un User partageant un material ne
//!   réutilisent pas la même clé de protection DHT.
//!
//! Règle de fixtures : constantes internes arbitraires (graines RFC 8032
//! §7.1 réutilisées comme graines d'entrée seulement — jamais comme valeurs
//! attendues).

use p2p_storage_core::k_node_self::derive_k_node_self;
use p2p_storage_core::k_self::derive_k_self;

/// RFC 8032 §7.1 TEST 1 — graine d'entrée seulement.
const SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
/// RFC 8032 §7.1 TEST 2 — graine d'entrée seulement.
const OTHER_SEED: [u8; 32] = [
    0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
    0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
];

/// Mêmes entrées -> même `K_node_self`, clé non nulle (restauration
/// complète depuis la seed seule — page spec, §« Ce qu'elle protège »).
#[test]
fn k_node_self_derivation_is_deterministic() {
    let k1 = derive_k_node_self(&SEED).expect("HKDF");
    let k2 = derive_k_node_self(&SEED).expect("HKDF");
    assert_eq!(k1, k2);
    assert_ne!(k1, [0u8; 32]);
}

/// Deux graines Nœud distinctes -> clés distinctes (seul le Nœud via sa
/// propre seed peut déchiffrer sa cartographie).
#[test]
fn k_node_self_differs_per_priv_node() {
    let k_a = derive_k_node_self(&SEED).expect("HKDF");
    let k_b = derive_k_node_self(&OTHER_SEED).expect("HKDF");
    assert_ne!(k_a, k_b);
}

/// Séparation de domaine : une même graine sous `info = "node-recovery"`
/// et sous `info = "attachment-recovery"` donne deux clés distinctes —
/// `K_node_self` (Nœud) et `K_self` (User) ne réutilisent jamais le même
/// material même en cas de graine identique.
#[test]
fn k_node_self_is_domain_separated_from_k_self() {
    let node = derive_k_node_self(&SEED).expect("HKDF");
    let user = derive_k_self(&SEED).expect("HKDF");
    assert_ne!(node, user);
}
