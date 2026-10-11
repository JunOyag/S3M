//! Vecteurs et invariants pour `crypto.k-block` (Phase 0).
//!
//! Pas de vecteur externe publié pour cette dérivation : elle est propre au
//! protocole (`K_block = KDF(master_key[version], block_hash,
//! encryption_salt)`, voir `docs/03-crypto/k-block.md`). Les tests ci-dessous
//! vérifient donc les invariants structurels exigés par la page :
//! - déterminisme (mêmes entrées -> même clé) ;
//! - une clé distincte par bloc (`block_hash` seul fait varier la clé —
//!   révocabilité individuelle) ;
//! - `encryption_salt` fait varier la clé (un fichier/répertoire = un salt
//!   -> des clés distinctes à `block_hash` égal) ;
//! - `master_key[version]` fait varier la clé (rotation -> nouvelles clés,
//!   voir `crypto.master-key-chain`) ;
//! - la clé produite n'est jamais nulle.
//!
//! Règle de fixtures : les entrées ci-dessous sont des constantes de test
//! internes arbitraires, jamais des valeurs attendues produites par le code.

use p2p_storage_core::k_block::derive_k_block;

const MASTER_KEY_V0: [u8; 32] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
];
const MASTER_KEY_V1: [u8; 32] = [
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
];
const BLOCK_HASH_A: [u8; 32] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
];
const BLOCK_HASH_B: [u8; 32] = [
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
];

/// Mêmes entrées -> même `K_block`, et clé non nulle.
#[test]
fn k_block_derivation_is_deterministic() {
    let salt = b"encryption-salt-fichier-1";
    let k1 = derive_k_block(&MASTER_KEY_V0, &BLOCK_HASH_A, salt).expect("KDF");
    let k2 = derive_k_block(&MASTER_KEY_V0, &BLOCK_HASH_A, salt).expect("KDF");
    assert_eq!(k1, k2);
    assert_ne!(k1, [0u8; 32]);
}

/// Deux blocs du même fichier (même salt, `block_hash` distincts) -> clés
/// distinctes. C'est l'invariant « une clé distincte par bloc, révocable
/// individuellement » de la page spec.
#[test]
fn k_block_differs_per_block_hash() {
    let salt = b"encryption-salt-fichier-1";
    let k_a = derive_k_block(&MASTER_KEY_V0, &BLOCK_HASH_A, salt).expect("KDF");
    let k_b = derive_k_block(&MASTER_KEY_V0, &BLOCK_HASH_B, salt).expect("KDF");
    assert_ne!(k_a, k_b);
}

/// Même `block_hash`, salts distincts (deux fichiers/répertoires) -> clés
/// distinctes. `encryption_salt` est fixé une fois par fichier/répertoire
/// (page spec) : il doit effectivement séparer les domaines.
#[test]
fn k_block_differs_per_encryption_salt() {
    let k1 = derive_k_block(&MASTER_KEY_V0, &BLOCK_HASH_A, b"salt-fichier-1").expect("KDF");
    let k2 = derive_k_block(&MASTER_KEY_V0, &BLOCK_HASH_A, b"salt-fichier-2").expect("KDF");
    assert_ne!(k1, k2);
}

/// Rotation de `master_key` (même bloc, même salt) -> clé distincte. Les
/// blocs nouvellement écrits après une rotation utilisent la clé courante
/// (voir `crypto.master-key-chain`) : la dérivation doit suivre la version.
#[test]
fn k_block_differs_per_master_key_version() {
    let salt = b"encryption-salt-fichier-1";
    let k_v0 = derive_k_block(&MASTER_KEY_V0, &BLOCK_HASH_A, salt).expect("KDF");
    let k_v1 = derive_k_block(&MASTER_KEY_V1, &BLOCK_HASH_A, salt).expect("KDF");
    assert_ne!(k_v0, k_v1);
}
