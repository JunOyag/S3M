//! Vecteurs et invariants pour `crypto.k-block` (Phase 0).
//!
//! Formule de la page (`K_block = KDF(master_key[version], info =
//! "p2p-storage/block/v1", salt = encryption_salt)`, voir
//! `docs/03-crypto/k-block.md`) — **indépendante de `block_hash`**
//! (circularité arbitrée dans `impl/SPEC_GAPS.md` : une clé par élément,
//! révocable au niveau de l'élément). Les tests ci-dessous vérifient donc
//! les invariants structurels exigés par la page :
//! - déterminisme (mêmes entrées -> même clé) ;
//! - `encryption_salt` fait varier la clé (un fichier/répertoire = un salt
//!   -> des clés distinctes à `master_key` égale) ;
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

/// Mêmes entrées -> même `K_block`, et clé non nulle.
#[test]
fn k_block_derivation_is_deterministic() {
    let salt = b"encryption-salt-fichier-1";
    let k1 = derive_k_block(&MASTER_KEY_V0, salt).expect("KDF");
    let k2 = derive_k_block(&MASTER_KEY_V0, salt).expect("KDF");
    assert_eq!(k1, k2);
    assert_ne!(k1, [0u8; 32]);
}

/// Même `master_key`, salts distincts (deux éléments) -> clés distinctes.
/// `encryption_salt` est fixé une fois par fichier/répertoire (page spec) :
/// il doit effectivement séparer les domaines — c'est lui, et non
/// `block_hash`, qui distingue désormais les clés.
#[test]
fn k_block_differs_per_encryption_salt() {
    let k1 = derive_k_block(&MASTER_KEY_V0, b"salt-fichier-1").expect("KDF");
    let k2 = derive_k_block(&MASTER_KEY_V0, b"salt-fichier-2").expect("KDF");
    assert_ne!(k1, k2);
}

/// Rotation de `master_key` (même salt) -> clé distincte. Les blocs
/// nouvellement écrits après une rotation utilisent la clé courante
/// (voir `crypto.master-key-chain`) : la dérivation doit suivre la version.
#[test]
fn k_block_differs_per_master_key_version() {
    let salt = b"encryption-salt-fichier-1";
    let k_v0 = derive_k_block(&MASTER_KEY_V0, salt).expect("KDF");
    let k_v1 = derive_k_block(&MASTER_KEY_V1, salt).expect("KDF");
    assert_ne!(k_v0, k_v1);
}
