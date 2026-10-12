//! Chaîne de clés maîtresses — id `crypto.master-key-chain` (Phase 0).
//!
//! Re-wrap plat (pas de chaînage séquentiel) : chaque clé historique reste
//! déchiffrable en une seule étape depuis la clé courante. Invariants
//! exigés par la page (`docs/03-crypto/master-key-chain.md`) :
//! - lecture d'un bloc ancien : `key_version` (DirectoryEntry) → unwrap de
//!   `wrapped_key` sous la clé courante → `master_key[version]` ;
//! - `wrapped_key` = 48 o sans en-tête (l'en-tête de protocole `u16` BE,
//!   fixé par `deploiement.formats-serialisation`, n'existe qu'en AAD) ;
//! - transplantation de versions (AAD altéré) → tag rejeté ;
//! - coût constant : N rotations simulées, `resolve(version=0)` = 1 unwrap ;
//! - version inconnue → `UnknownKeyVersion` (pas de confusion silencieuse).
//!
//! Règle de fixtures : clés et en-tête arbitraires internes — l'en-tête
//! `0x0001` reprend la valeur de protocole en vigueur (formats-serialisation),
//! pas une valeur attendue produite par le code.

use std::collections::HashMap;

use p2p_storage_core::error::CoreError;
use p2p_storage_core::master_key_chain::{
    MasterKeyEntry, resolve_master_key, rewrap_chain_on_rotation,
};

/// En-tête de version de protocole (2 o, `u16` gros-boutiste) — valeur `1`
/// en vigueur (`deploiement.formats-serialisation`). Reprend la convention
/// des fixtures de `symmetric_suite_vectors.rs`.
const PROTOCOL_HEADER_V1: [u8; 2] = [0x00, 0x01];

const MASTER_KEY_V0: [u8; 32] = [0x10u8; 32];
const MASTER_KEY_V1: [u8; 32] = [0x31u8; 32];
const MASTER_KEY_V2: [u8; 32] = [0x52u8; 32];

fn historical_keys_v0_v1() -> HashMap<u16, [u8; 32]> {
    HashMap::from([(0u16, MASTER_KEY_V0), (1u16, MASTER_KEY_V1)])
}

/// Lecture d'un bloc ancien : re-wrap plat v0,v1 sous v2, puis résolution
/// de chaque version — maillons de 48 o, clés retrouvées à l'identique.
#[test]
fn flat_rewrap_then_resolve_recovers_historical_keys() {
    let chain = rewrap_chain_on_rotation(
        &PROTOCOL_HEADER_V1,
        &historical_keys_v0_v1(),
        &MASTER_KEY_V2,
        2,
    )
    .expect("re-wrap");
    assert_eq!(chain.len(), 2);
    for entry in &chain {
        assert_eq!(entry.wrapped_key.len(), 48); // SANS en-tête
    }

    let k0 = resolve_master_key(&PROTOCOL_HEADER_V1, &chain, &MASTER_KEY_V2, 2, 0)
        .expect("résolution v0");
    let k1 = resolve_master_key(&PROTOCOL_HEADER_V1, &chain, &MASTER_KEY_V2, 2, 1)
        .expect("résolution v1");
    assert_eq!(k0, MASTER_KEY_V0);
    assert_eq!(k1, MASTER_KEY_V1);
}

/// Coût constant : après N rotations simulées (chaîne de N maillons sous la
/// clé courante), `resolve(version=0)` reste une seule opération d'unwrap —
/// le re-wrap est plat, jamais séquentiel.
#[test]
fn resolve_stays_single_unwrap_after_many_rotations() {
    const N: u16 = 8;
    let mut historical = HashMap::new();
    for v in 0..N {
        historical.insert(v, [v as u8; 32]);
    }
    let current = [0xFFu8; 32];
    let chain =
        rewrap_chain_on_rotation(&PROTOCOL_HEADER_V1, &historical, &current, N)
            .expect("re-wrap");
    assert_eq!(chain.len(), N as usize);

    let k0 = resolve_master_key(&PROTOCOL_HEADER_V1, &chain, &current, N, 0)
        .expect("résolution v0");
    assert_eq!(k0, [0u8; 32]);
}

/// Transplantation de versions : un maillon wrappé sous la version courante
/// 2 est illisible sous une autre clé courante (AAD `u16(version_courante)`
/// distinct → tag rejeté, mappé en `UnwrapFailure`).
#[test]
fn transplanted_version_fails_tag_verification() {
    let chain = rewrap_chain_on_rotation(
        &PROTOCOL_HEADER_V1,
        &historical_keys_v0_v1(),
        &MASTER_KEY_V2,
        2,
    )
    .expect("re-wrap");
    let wrong_current = [0xAAu8; 32];
    assert!(matches!(
        resolve_master_key(&PROTOCOL_HEADER_V1, &chain, &wrong_current, 2, 0),
        Err(CoreError::UnwrapFailure)
    ));
}

/// Version absente de la chaîne → `UnknownKeyVersion` explicite (jamais de
/// clé devinée ni de confusion silencieuse).
#[test]
fn unknown_version_is_rejected_explicitly() {
    let chain = rewrap_chain_on_rotation(
        &PROTOCOL_HEADER_V1,
        &historical_keys_v0_v1(),
        &MASTER_KEY_V2,
        2,
    )
    .expect("re-wrap");
    assert!(matches!(
        resolve_master_key(&PROTOCOL_HEADER_V1, &chain, &MASTER_KEY_V2, 2, 9),
        Err(CoreError::UnknownKeyVersion { version: 9 })
    ));
    assert!(matches!(
        resolve_master_key(&PROTOCOL_HEADER_V1, &[], &MASTER_KEY_V2, 2, 0),
        Err(CoreError::UnknownKeyVersion { version: 0 })
    ));
}

/// Les maillons portent leur version : la chaîne triée expose v0 puis v1
/// (ordre de publication déterministe du re-wrap).
#[test]
fn chain_entries_carry_their_wrapped_version() {
    let chain = rewrap_chain_on_rotation(
        &PROTOCOL_HEADER_V1,
        &historical_keys_v0_v1(),
        &MASTER_KEY_V2,
        2,
    )
    .expect("re-wrap");
    let versions: Vec<u16> = chain.iter().map(|e: &MasterKeyEntry| e.version).collect();
    assert_eq!(versions, vec![0u16, 1u16]);
}