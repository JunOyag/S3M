//! Invariants de `protocols.tombstones`.

use std::collections::HashSet;

use p2p_storage_node::tombstones::*;

const SENDER_SEED: [u8; 32] = [0x51; 32];

fn sender_pub() -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(&SENDER_SEED)
        .verifying_key()
        .to_bytes()
}

fn hosted() -> HashSet<[u8; 32]> {
    [[1u8; 32], [2; 32], [3; 32]].into()
}

/// Libération bilatérale équivalente : le récepteur libère les blocs
/// effectivement hébergés et décrémente son compte ; l'émetteur décrémente
/// le sien du même nombre à l'accusé de réception.
#[test]
fn bilateral_release_keeps_both_accounts_equivalent() {
    let mut store = hosted();
    let mut receiver = PartnerLedger {
        hosted_by_partner: 3,
        ..Default::default()
    };
    let mut sender = PartnerLedger {
        hosted_for_partner: 3,
        ..Default::default()
    };
    // [9; 32] n'est pas hébergé : ignoré, non compté.
    let notice = TombstoneNotice::sign(&SENDER_SEED, 100, vec![[1; 32], [3; 32], [9; 32]]);
    let freed = apply_received(&mut receiver, &sender_pub(), &notice, &mut |h| {
        store.remove(h)
    })
    .unwrap();
    assert_eq!(freed, 2);
    assert_eq!(store, [[2u8; 32]].into());
    apply_acknowledged(&mut sender, freed);
    assert_eq!(receiver.hosted_by_partner, 1);
    assert_eq!(sender.hosted_for_partner, 1);
}

/// Preuve d'identité : un avis signé par une autre clé, ou altéré, est rejeté
/// sans rien libérer.
#[test]
fn forged_or_altered_notices_free_nothing() {
    let mut store = hosted();
    let mut ledger = PartnerLedger {
        hosted_by_partner: 3,
        ..Default::default()
    };
    let forged = TombstoneNotice::sign(&[0x52; 32], 100, vec![[1; 32]]);
    assert!(
        apply_received(&mut ledger, &sender_pub(), &forged, &mut |h| store
            .remove(h))
        .is_err()
    );
    let mut altered = TombstoneNotice::sign(&SENDER_SEED, 100, vec![[1; 32]]);
    altered.block_hashes.push([2; 32]);
    assert!(
        apply_received(&mut ledger, &sender_pub(), &altered, &mut |h| store
            .remove(h))
        .is_err()
    );
    assert_eq!(store.len(), 3);
    assert_eq!(ledger.hosted_by_partner, 3);
}

/// Anti-rejeu : un avis de timestamp inférieur ou égal au dernier appliqué
/// est refusé.
#[test]
fn replayed_notices_are_refused() {
    let mut store = hosted();
    let mut ledger = PartnerLedger {
        hosted_by_partner: 3,
        ..Default::default()
    };
    let n1 = TombstoneNotice::sign(&SENDER_SEED, 100, vec![[1; 32]]);
    apply_received(&mut ledger, &sender_pub(), &n1, &mut |h| store.remove(h)).unwrap();
    assert!(matches!(
        apply_received(&mut ledger, &sender_pub(), &n1, &mut |h| store.remove(h)),
        Err(TombstoneError::Replay)
    ));
    let older = TombstoneNotice::sign(&SENDER_SEED, 99, vec![[2; 32]]);
    assert!(matches!(
        apply_received(&mut ledger, &sender_pub(), &older, &mut |h| store.remove(h)),
        Err(TombstoneError::Replay)
    ));
    assert_eq!(store.len(), 2);
}

/// Séparation de contexte : une signature d'avis ne vaut pas signature
/// d'entrée DHT, et réciproquement.
#[test]
fn tombstone_label_is_distinct_from_dht_labels() {
    use p2p_storage_protocol::dht::{EntryKind, SIG_LABEL_MIGRATION_POINTER};
    for k in [
        EntryKind::Node,
        EntryKind::User,
        EntryKind::Dispersal,
        EntryKind::Emergency,
    ] {
        assert_ne!(k.signature_label(), SIG_LABEL_TOMBSTONE);
    }
    assert_ne!(SIG_LABEL_MIGRATION_POINTER, SIG_LABEL_TOMBSTONE);
}
