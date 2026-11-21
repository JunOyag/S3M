//! Snapshot du NodeManifest (`deploiement.disaster-recovery` § Snapshot).

use s3m_core::vdf::VdfProof;
use s3m_protocol::dispersal::{BlockRef, PartnerDesc, StripeDesc};
use s3m_protocol::entries::{node_entry_envelope, NodeEntryParams};
use s3m_protocol::snapshot::*;

fn desc(users: usize) -> SnapshotDesc {
    SnapshotDesc {
        node_id: [1; 32],
        users: (0..users)
            .map(|i| SnapUser {
                user_id: [i as u8; 32],
                salt: vec![i as u8; 16],
                quota_bytes: 1 << 30,
                attached_at: i as u64,
            })
            .collect(),
        partners: vec![SnapPartner {
            node_id: [9; 32],
            hosted_for_partner: 3,
            hosted_by_partner: 4,
            allowance: 1_000,
        }],
        blacklist: vec![([8; 32], 77, "pos_invalid_response".into())],
        timestamp: 42,
    }
}

#[test]
fn manifest_roundtrips_users_partners_allowance_and_blacklist() {
    let d = desc(3);
    assert_eq!(decode_manifest(&encode_manifest(&d)).unwrap(), d);
}

/// Un gros manifeste s'étale sur plusieurs blocs ; mauvais sel = illisible.
#[test]
fn snapshot_spans_the_k_blocks_and_needs_the_node_key_and_salt() {
    let d = desc(1_500);
    let m = encode_manifest(&d);
    assert!(m.len() > 65_506, "plus d'un bloc : {}", m.len());
    let mut n = 0u8;
    let mut nonce = || {
        n += 1;
        [n; 12]
    };
    let frames = seal_snapshot(&[5; 32], &[6; 16], 4, &m, &mut nonce).unwrap();
    assert_eq!(frames.len(), 4);
    assert!(frames.iter().all(|f| f.len() == 65_536));
    assert_eq!(
        decode_manifest(&open_snapshot(&[5; 32], &[6; 16], &frames).unwrap()).unwrap(),
        d
    );
    assert!(open_snapshot(&[5; 32], &[7; 16], &frames).is_err());
    assert!(open_snapshot(&[4; 32], &[6; 16], &frames).is_err());
    assert!(seal_snapshot(&[5; 32], &[6; 16], 1, &m, &mut nonce).is_err());
}

#[test]
fn pointer_travels_encrypted_in_the_node_entry() {
    let p = SnapshotPointer {
        root_hash: [3; 32],
        partners: vec![PartnerDesc {
            partner_id: 1,
            node_id: [9; 32],
            ip: "203.0.113.1".into(),
            port: 4002,
        }],
        salt: [6; 16],
        stripe: StripeDesc {
            stripe_id: [2; 32],
            k: 2,
            m: 3,
            blocks: vec![BlockRef {
                hash: [4; 32],
                index: 2,
                partner_id: 1,
                key_version: 1,
                is_padding: false,
            }],
            encryption_salt: Some([6; 16]),
        },
    };
    let seed = [5u8; 32];
    let env = node_entry_envelope(
        &seed,
        &NodeEntryParams {
            ip: "203.0.113.2",
            port: 4002,
            timestamp: 1,
            proof: &VdfProof {
                y: vec![1; 100],
                pi: vec![2; 100],
            },
            pub_node_recovery: &[0; 32],
            snapshot_pointer: Some(&encode_pointer(&p)),
            addrs: &[],
            pub_node_announce: None,
            name: None,
        },
        &[1; 12],
    )
    .unwrap();
    assert_eq!(open_node_entry_pointer(&seed, &env).unwrap(), Some(p));
    assert!(open_node_entry_pointer(&[6; 32], &env).is_err());
}
