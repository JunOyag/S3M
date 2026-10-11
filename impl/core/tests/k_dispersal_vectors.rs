//! Vecteurs et invariants pour `crypto.k-dispersal` (Phase 0).
//!
//! Pas de vecteur externe publié : dérivation propre au protocole
//! (`K_dispersal_content = KDF(K_attach, "dispersal-content")`,
//! `K_dispersal_block = KDF(K_dispersal_content, block_hash)` — voir
//! `docs/03-crypto/k-dispersal.md`). Invariants structurels exigés par la
//! page :
//! - déterminisme des deux étages ;
//! - une clé distincte par bloc (`block_hash` seul fait varier
//!   `K_dispersal_block`) ;
//! - séparation de domaine : pour un même `K_attach`, `K_dispersal_content`
//!   est distinct de `K_attach` lui-même et de `sig_priv_dispersal`
//!   (= `KDF(K_attach, "dispersal-signing")`) — transmettre le premier ne
//!   donne ni la clé racine ni la capacité de signature ;
//! - sens unique : aucune fonction du module ne reconstitue `K_attach`
//!   depuis `K_dispersal_content` (garanti par l'absence de code dans ce
//!   sens — HKDF n'étant pas inversible ; le test fige ici qu'une entrée
//!   `K_dispersal_content` arbitraire redérivée ne redonne jamais le
//!   `K_attach` d'origine).
//!
//! Règle de fixtures : constantes de test internes arbitraires, jamais des
//! valeurs attendues produites par le code.

use p2p_storage_core::k_attach::derive_sig_priv_dispersal;
use p2p_storage_core::k_dispersal::{derive_k_dispersal_block, derive_k_dispersal_content};

const K_ATTACH: [u8; 32] = [
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
];
const OTHER_K_ATTACH: [u8; 32] = [0x77u8; 32];
const BLOCK_HASH_A: [u8; 32] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
];
const BLOCK_HASH_B: [u8; 32] = [
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
];

/// Les deux étages sont déterministes, non nuls, et sensibles à leur entrée
/// (`K_attach` distinct -> `K_dispersal_content` distinct).
#[test]
fn k_dispersal_derivation_is_deterministic() {
    let c1 = derive_k_dispersal_content(&K_ATTACH).expect("HKDF");
    let c2 = derive_k_dispersal_content(&K_ATTACH).expect("HKDF");
    let c_other = derive_k_dispersal_content(&OTHER_K_ATTACH).expect("HKDF");
    assert_eq!(c1, c2);
    assert_ne!(c1, [0u8; 32]);
    assert_ne!(c1, c_other);

    let b1 = derive_k_dispersal_block(&c1, &BLOCK_HASH_A).expect("HKDF");
    let b2 = derive_k_dispersal_block(&c1, &BLOCK_HASH_A).expect("HKDF");
    assert_eq!(b1, b2);
    assert_ne!(b1, [0u8; 32]);
}

/// Deux blocs internes (`block_hash` distincts, même `K_dispersal_content`)
/// -> `K_dispersal_block` distincts (même principe que `K_block`).
#[test]
fn k_dispersal_block_differs_per_block_hash() {
    let content = derive_k_dispersal_content(&K_ATTACH).expect("HKDF");
    let b_a = derive_k_dispersal_block(&content, &BLOCK_HASH_A).expect("HKDF");
    let b_b = derive_k_dispersal_block(&content, &BLOCK_HASH_B).expect("HKDF");
    assert_ne!(b_a, b_b);
}

/// Séparation de domaine (page spec, §« Séparation délibérée en deux
/// étages ») : `K_dispersal_content` transmis en migration ne révèle ni
/// `K_attach` ni `sig_priv_dispersal` — les trois valeurs co-dérivées du
/// même `K_attach` sont deux à deux distinctes.
#[test]
fn k_dispersal_content_is_domain_separated_from_k_attach_and_signing_key() {
    let content = derive_k_dispersal_content(&K_ATTACH).expect("HKDF");
    let sig_priv = derive_sig_priv_dispersal(&K_ATTACH).expect("HKDF");
    assert_ne!(content, K_ATTACH);
    assert_ne!(content, sig_priv);
    assert_ne!(sig_priv, K_ATTACH);
}
