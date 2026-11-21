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

// ------------------------------------------------ partenaire de secours

use s3m_node::chunk_store::Space;
use s3m_node::exchange::NodeService;
use s3m_protocol::exchange::*;

const PARTNER: [u8; 32] = [0x20; 32];
const NOW: u64 = 1_000_000;

fn pk(s: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(s)
        .verifying_key()
        .to_bytes()
}

fn partner(per_depositor: u64) -> NodeService {
    let mut s = NodeService::new(PARTNER);
    s.vdf = Some(std::sync::Arc::new(|_, _| true));
    s.emergency = EmergencyReserve::with_cap(2, per_depositor);
    s
}

/// `EmergencyPut` de l'identité VDF `user` sous la clé de secours `epub`,
/// sur la connexion `from` → `p`.
fn put(user: &[u8; 32], epub: &[u8; 32], from: &[u8], data: Vec<u8>) -> Request {
    Request {
        credential: Some(Credential::Emergency {
            sig_pub_user: pk(user).to_vec(),
            vdf_y: vec![1],
            vdf_pi: vec![2],
            emergency_pub: epub.to_vec(),
            signature: emergency_deposit_signature(user, epub, from, b"p"),
        }),
        body: Body::EmergencyPut { data },
    }
}

#[test]
fn deposits_need_a_bound_vdf_identity_and_respect_the_reserve() {
    let mut s = partner(100);
    let keys = s3m_protocol::emergency::emergency_keys(&[9; 32]).unwrap();
    let epub = keys.sig_pub;
    let h = s3m_core::symmetric_suite::hash_sha256(&[1; 60]);
    assert_eq!(
        s.handle(
            b"c",
            None,
            b"p",
            put(&[3; 32], &epub, b"c", vec![1; 60]),
            NOW
        ),
        Response::Stored(h.to_vec())
    );
    // Preuve rejouée depuis une autre connexion.
    assert_eq!(
        s.handle(
            b"x",
            None,
            b"p",
            put(&[3; 32], &epub, b"c", vec![2; 30]),
            NOW
        ),
        Response::Failure(Refusal::Unauthorized)
    );
    // Plafond par déposant (100 o).
    assert_eq!(
        s.handle(
            b"c",
            None,
            b"p",
            put(&[3; 32], &epub, b"c", vec![2; 50]),
            NOW
        ),
        Response::Failure(Refusal::QuotaExceeded)
    );
    // Même identité VDF, autre clé de secours : refusée tant que la première a des blocs.
    assert_eq!(
        s.handle(
            b"c",
            None,
            b"p",
            put(&[3; 32], &[7; 32], b"c", vec![3; 10]),
            NOW
        ),
        Response::Failure(Refusal::QuotaExceeded)
    );
    // Sans preuve VDF valide : refusé.
    s.vdf = Some(std::sync::Arc::new(|_, _| false));
    assert_eq!(
        s.handle(
            b"c",
            None,
            b"p",
            put(&[4; 32], &[8; 32], b"c", vec![4; 10]),
            NOW
        ),
        Response::Failure(Refusal::Unauthorized)
    );
    // Relecture par la clé de secours seulement.
    let get = |e: &[u8; 32]| Request {
        credential: None,
        body: Body::EmergencyGet {
            emergency_pub: e.to_vec(),
            hash: h.to_vec(),
        },
    };
    assert_eq!(
        s.handle(b"n", None, b"p", get(&epub), NOW),
        Response::BlockData(vec![1; 60])
    );
    assert_eq!(
        s.handle(b"n", None, b"p", get(&[7; 32]), NOW),
        Response::Failure(Refusal::NotFound)
    );
    // Libération signée par sig_priv_emergency, sans rejeu.
    let release = |ts| Request {
        credential: None,
        body: emergency_release(&keys.sig_priv, ts, &[h]),
    };
    assert_eq!(
        s.handle(b"n", None, b"p", release(5), NOW),
        Response::Ack { freed: 1 }
    );
    assert_eq!(s.emergency.users(), 0);
    assert!(s.store.get(Space::Emergency, &h).is_none());
    let forged = Request {
        credential: None,
        body: emergency_release(&[1; 32], 6, &[h]),
    };
    let Body::EmergencyRelease {
        hashes,
        timestamp,
        signature,
        ..
    } = forged.body
    else {
        panic!()
    };
    let forged = Request {
        credential: None,
        body: Body::EmergencyRelease {
            emergency_pub: epub.to_vec(),
            timestamp,
            hashes,
            signature,
        },
    };
    assert_eq!(
        s.handle(b"n", None, b"p", forged, NOW),
        Response::Failure(Refusal::Unauthorized)
    );
}

#[test]
fn release_replay_is_refused_and_forgotten_deposits_are_purged() {
    let mut s = partner(1000);
    let keys = s3m_protocol::emergency::emergency_keys(&[9; 32]).unwrap();
    for i in 1..=2u8 {
        s.handle(
            b"c",
            None,
            b"p",
            put(&[3; 32], &keys.sig_pub, b"c", vec![i; 60]),
            NOW,
        );
    }
    let h1 = s3m_core::symmetric_suite::hash_sha256(&[1; 60]);
    let release = |ts| Request {
        credential: None,
        body: emergency_release(&keys.sig_priv, ts, &[h1]),
    };
    assert_eq!(
        s.handle(b"n", None, b"p", release(5), NOW),
        Response::Ack { freed: 1 }
    );
    assert_eq!(
        s.handle(b"n", None, b"p", release(5), NOW),
        Response::Failure(Refusal::Replayed)
    );
    assert_eq!(s.emergency.used_bytes(), 60);
    assert_eq!(s.purge_emergency(NOW + DEPOSIT_RETENTION_S - 1), 0);
    assert_eq!(s.purge_emergency(NOW + DEPOSIT_RETENTION_S), 1);
    assert_eq!(s.emergency.users(), 0);
    assert!(s.store.owners(Space::Emergency).is_empty());
}

#[test]
fn reserve_is_sized_from_u_backup_and_rebuilt_from_storage() {
    let mut r = EmergencyReserve::default();
    assert_eq!(r.reserved_bytes, 20 << 30);
    r.set_limits(5, 2 << 30);
    assert_eq!(r.reserved_bytes, 10 << 30);
    r.rebuild(&[([1; 32], 65_536)], NOW);
    assert_eq!((r.users(), r.used_bytes()), (1, 65_536));
    r.rebuild(&[], NOW);
    assert_eq!(r.users(), 0);
    let _ = pk(&PARTNER);
}
