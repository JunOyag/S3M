//! Registres d'étiquettes — id `crypto.symmetric-suite` (spec V3).
//!
//! Invariants de la page (« Registre des étiquettes KDF », « AAD ») :
//! 1. **unicité globale** de chaque étiquette dans son registre ;
//! 2. **contenu exact** — les chaînes sont celles publiées par la page ;
//! 3. **immuabilité** — aucune étiquette retirée en V3 n'est réutilisée.

use std::collections::HashSet;

use s3m_core::labels::{
    AAD_CONTEXT_MASTER_KEY_WRAP, ALL_AAD_CONTEXTS, ALL_KDF_LABELS, ATTACH, ATTACHMENT_RECOVERY,
    BLOCK, CONNECTOR_AUTH, DHT_LOOKUP, DHT_SIGNING, DISPERSAL_BLOCK, DISPERSAL_CONTENT,
    DISPERSAL_SIGNING, EMERGENCY_CONTENT, EMERGENCY_SIGNING, KDF_PREFIX, MASTER_KEY_WRAP,
    NODE_RECOVERY, NODE_SNAPSHOT, RETIRED_LABELS,
};

#[test]
fn kdf_labels_are_globally_unique() {
    let set: HashSet<_> = ALL_KDF_LABELS.iter().collect();
    assert_eq!(set.len(), ALL_KDF_LABELS.len());
    assert!(ALL_KDF_LABELS.iter().all(|l| !l.is_empty()));
}

#[test]
fn aad_contexts_are_unique() {
    let set: HashSet<_> = ALL_AAD_CONTEXTS.iter().collect();
    assert_eq!(set.len(), ALL_AAD_CONTEXTS.len());
}

#[test]
fn retired_labels_are_never_reused() {
    for retired in RETIRED_LABELS {
        assert!(!ALL_KDF_LABELS.contains(&retired), "{retired}");
        assert_ne!(retired, KDF_PREFIX);
    }
}

#[test]
fn labels_match_the_spec_registry() {
    assert_eq!(KDF_PREFIX, "s3m/kdf/v1");
    let expected = [
        (ATTACH, "attach"),
        (DISPERSAL_SIGNING, "dispersal-signing"),
        (DISPERSAL_CONTENT, "dispersal-content"),
        (DISPERSAL_BLOCK, "dispersal-block"),
        (EMERGENCY_CONTENT, "emergency-content"),
        (EMERGENCY_SIGNING, "emergency-signing"),
        (ATTACHMENT_RECOVERY, "attachment-recovery"),
        (NODE_RECOVERY, "node-recovery"),
        (DHT_LOOKUP, "dht-lookup"),
        (DHT_SIGNING, "dht-signing"),
        (BLOCK, "block"),
        (MASTER_KEY_WRAP, "master-key-wrap"),
        (CONNECTOR_AUTH, "connector-auth"),
        (NODE_SNAPSHOT, "node-snapshot"),
    ];
    for (got, want) in expected {
        assert_eq!(got, want);
    }
    assert_eq!(ALL_KDF_LABELS.len(), 14);
    assert_eq!(AAD_CONTEXT_MASTER_KEY_WRAP, "master-key-wrap");
}
