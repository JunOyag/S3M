//! Invariants de `protocols.quota-sync` (partie node).

use p2p_storage_node::quota_sync::*;

fn w(ts: u64, c: u32, h: u8) -> PendingWrite {
    PendingWrite {
        timestamp: ts,
        connector: c,
        block_hash: [h; 32],
    }
}

/// Deux Connecteurs hors-ligne respectant chacun le quota connu : la somme
/// dépasse ; intégration par timestamp croissant, tous appareils confondus,
/// et rejet des suivants vers leur Connecteur d'origine.
#[test]
fn writes_are_integrated_by_timestamp_across_connectors_until_quota() {
    let writes = vec![w(1, 1, 1), w(4, 1, 2), w(2, 2, 3), w(5, 2, 4), w(3, 1, 5)];
    let r = integrate(writes, 3, &|_| false);
    assert_eq!(r.accepted, vec![[1; 32], [3; 32], [5; 32]]);
    assert_eq!(r.rejected.get(&1), Some(&vec![[2u8; 32]]));
    assert_eq!(r.rejected.get(&2), Some(&vec![[4u8; 32]]));
}

/// Un bloc déjà stocké ou reçu deux fois ne consomme pas de quota.
#[test]
fn duplicate_blocks_do_not_consume_quota() {
    let writes = vec![w(1, 1, 1), w(2, 2, 1), w(3, 1, 2), w(4, 2, 3)];
    let r = integrate(writes, 1, &|h| h == &[2u8; 32]);
    assert_eq!(r.accepted, vec![[1; 32]]);
    assert_eq!(r.rejected.get(&2), Some(&vec![[3u8; 32]]));
    assert_eq!(r.rejected.get(&1), None);
}
