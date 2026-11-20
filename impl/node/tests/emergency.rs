//! Invariants de `protocols.espace-secours` (partie node).

use s3m_node::emergency::*;
use s3m_node::quota_sync::PendingWrite;
use s3m_protocol::dht::emergency_dht_key;

#[test]
fn reserve_caps_users_and_bytes() {
    let mut r = EmergencyReserve::new(2, 100);
    r.accept([1; 32], 40).unwrap();
    r.accept([2; 32], 40).unwrap();
    assert_eq!(r.accept([3; 32], 1), Err(ReservationError::TooManyUsers));
    assert_eq!(r.accept([1; 32], 21), Err(ReservationError::NoSpace));
    r.accept([1; 32], 20).unwrap();
    r.release(&[2; 32]);
    assert_eq!(r.users(), 1);
    r.accept([3; 32], 40).unwrap();
}

#[test]
fn return_integration_uses_emergency_keys_and_timestamp_order_until_quota() {
    let keys = emergency_keys(&[[7; 32], [8; 32]]);
    assert_eq!(
        keys,
        vec![emergency_dht_key(&[7; 32]), emergency_dht_key(&[8; 32])]
    );
    let w = |ts, h| PendingWrite {
        timestamp: ts,
        connector: 0,
        block_hash: [h; 32],
    };
    let r = integrate_emergency(vec![w(3, 3), w(1, 1), w(2, 2)], 2, &|_| false);
    assert_eq!(r.accepted, vec![[1; 32], [2; 32]]);
    assert_eq!(r.rejected.get(&0), Some(&vec![[3u8; 32]]));
}
