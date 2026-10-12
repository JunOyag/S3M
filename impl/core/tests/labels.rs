//! Test d'unicité et de contenu des registres d'étiquettes — id
//! `crypto.symmetric-suite` (Phase 0). Réf. spec :
//! docs/03-crypto/symmetric-suite.md, sections « Registre des étiquettes
//! KDF » et « Contextes d'AAD ».
//!
//! Règles testées, séparément pour chaque registre :
//! 1. **unicité globale** — une étiquette n'apparaît qu'une fois, quel que
//!    soit le secret d'entrée ou la page qui la définit ;
//! 2. **contenu exact** — les chaînes sont celles publiées par la page.

use p2p_storage_core::labels::{
    ALL_AAD_CONTEXTS, ALL_INFO_LABELS, AAD_CONTEXT_BLOCK, AAD_CONTEXT_MASTER_KEY_WRAP,
    ATTACHMENT_RECOVERY, DISPERSAL_BLOCK, DISPERSAL_CONTENT, DISPERSAL_SIGNING, DHT_LOOKUP,
    DHT_SIGNING, EMERGENCY_CONTENT, EMERGENCY_SIGNING, INFO_K_ATTACH_V1, NODE_RECOVERY,
    P2P_STORAGE_BLOCK_V1, P2P_STORAGE_MASTER_KEY_WRAP_V1, P2P_STORAGE_SYNTHETIC_NONCE_V1,
};

/// Unicité globale des 13 étiquettes `info` (dont l'exception `info` vide) :
/// une étiquette ne sert **jamais** à deux dérivations distinctes.
#[test]
fn info_labels_are_globally_unique() {
    for (i, a) in ALL_INFO_LABELS.iter().enumerate() {
        for b in &ALL_INFO_LABELS[i + 1..] {
            assert_ne!(a, b, "doublon dans le registre info : {:?}", a);
        }
    }
}

/// Unicité des contextes d'AAD (registre distinct du registre `info`) :
/// un contexte ne qualifie jamais deux chiffrés de nature différente.
#[test]
fn aad_contexts_are_unique() {
    for (i, a) in ALL_AAD_CONTEXTS.iter().enumerate() {
        for b in &ALL_AAD_CONTEXTS[i + 1..] {
            assert_ne!(a, b, "doublon dans le registre AAD : {:?}", a);
        }
    }
}

/// Les chaînes publiées par la page, à l'identique — garde-fou contre une
/// édition silencieuse de `labels.rs` qui casserait (silencieusement) toutes
/// les dérivations existantes.
#[test]
fn labels_match_the_spec_registry() {
    assert_eq!(INFO_K_ATTACH_V1, "");
    assert_eq!(DISPERSAL_SIGNING, "dispersal-signing");
    assert_eq!(DISPERSAL_CONTENT, "dispersal-content");
    assert_eq!(DISPERSAL_BLOCK, "dispersal-block");
    assert_eq!(ATTACHMENT_RECOVERY, "attachment-recovery");
    assert_eq!(NODE_RECOVERY, "node-recovery");
    assert_eq!(EMERGENCY_CONTENT, "emergency-content");
    assert_eq!(EMERGENCY_SIGNING, "emergency-signing");
    assert_eq!(DHT_LOOKUP, "dht-lookup");
    assert_eq!(DHT_SIGNING, "dht-signing");
    assert_eq!(P2P_STORAGE_BLOCK_V1, "p2p-storage/block/v1");
    assert_eq!(
        P2P_STORAGE_SYNTHETIC_NONCE_V1,
        "p2p-storage/synthetic-nonce/v1"
    );
    assert_eq!(
        P2P_STORAGE_MASTER_KEY_WRAP_V1,
        "p2p-storage/master-key-wrap/v1"
    );
    assert_eq!(ALL_INFO_LABELS.len(), 13);
    assert_eq!(AAD_CONTEXT_MASTER_KEY_WRAP, "master-key-wrap");
    assert_eq!(AAD_CONTEXT_BLOCK, "block");
}
