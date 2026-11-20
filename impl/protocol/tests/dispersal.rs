//! Catalogue de dispersion (`protocols.dispersion-transactionnelle`,
//! orchestration ; `protocols.index-adaptatif`).

use s3m_core::k_block::BLOCK_PLAINTEXT_LEN;
use s3m_protocol::dht::{accept_record, dispersal_dht_key};
use s3m_protocol::dispersal::*;

fn stripe(seed: u8, n: usize, salt: Option<[u8; 16]>) -> StripeDesc {
    StripeDesc {
        stripe_id: [seed; 32],
        k: 4,
        m: n as u8,
        blocks: (0..n)
            .map(|i| BlockRef {
                hash: [seed ^ i as u8; 32],
                index: i as u16,
                partner_id: if i < 4 { 0 } else { i as u16 },
                key_version: 1,
                is_padding: i == 3,
            })
            .collect(),
        encryption_salt: salt,
    }
}

fn partners(n: u16) -> Vec<PartnerDesc> {
    (1..=n)
        .map(|i| PartnerDesc {
            partner_id: i,
            node_id: [i as u8; 32],
            ip: "203.0.113.200".into(),
            port: 4002,
        })
        .collect()
}

#[test]
fn index_nodes_manifest_and_root_pointer_roundtrip() {
    let leaf = IndexNodeDesc {
        is_leaf: true,
        entries: vec![stripe(1, 16, None), stripe(2, 10, None)],
    };
    assert_eq!(decode_index_node(&encode_index_node(&leaf)).unwrap(), leaf);
    let inner = IndexNodeDesc {
        is_leaf: false,
        entries: vec![stripe(3, 16, Some([7; 16]))],
    };
    assert_eq!(
        decode_index_node(&encode_index_node(&inner)).unwrap(),
        inner
    );
    let m = ManifestDesc {
        user_id: [8; 32],
        node_id: [9; 32],
        partners: partners(12),
        root: inner,
        timestamp: 42,
    };
    assert_eq!(decode_manifest(&encode_manifest(&m)).unwrap(), m);
    let p = RootPointer {
        root_hash: [5; 32],
        partners: partners(12),
        salt: [6; 16],
        root_stripe: stripe(4, 16, Some([6; 16])),
    };
    assert_eq!(decode_root_pointer(&encode_root_pointer(&p)).unwrap(), p);
}

/// Les nœuds pleins (`INDEX_FANOUT` stripes complètes, N = 16, avec sels) et
/// la racine avec sa table de partenaires tiennent dans un bloc.
#[test]
fn full_index_nodes_fit_in_one_block() {
    let full: Vec<_> = (0..INDEX_FANOUT)
        .map(|i| stripe(i as u8, 16, Some([1; 16])))
        .collect();
    for is_leaf in [true, false] {
        let n = IndexNodeDesc {
            is_leaf,
            entries: full.clone(),
        };
        assert!(encode_index_node(&n).len() <= BLOCK_PLAINTEXT_LEN);
    }
    let m = ManifestDesc {
        user_id: [1; 32],
        node_id: [2; 32],
        partners: partners(48),
        root: IndexNodeDesc {
            is_leaf: true,
            entries: full,
        },
        timestamp: 1,
    };
    assert!(encode_manifest(&m).len() <= BLOCK_PLAINTEXT_LEN);
}

#[test]
fn dispersal_entry_is_accepted_by_the_dht_and_opens_under_k_attach() {
    let k = [3u8; 32];
    let p = RootPointer {
        root_hash: [5; 32],
        partners: partners(2),
        salt: [6; 16],
        root_stripe: stripe(4, 8, Some([6; 16])),
    };
    let env = dispersal_entry_envelope(&k, 1_000, &[1; 12], &p).unwrap();
    let key = dispersal_dht_key(&k);
    assert!(accept_record(&key, &env, None, 1_000, &|_, _| Ok(true)).is_ok());
    assert_eq!(open_dispersal_entry(&k, &env).unwrap(), p);
    assert!(open_dispersal_entry(&[4; 32], &env).is_err());
}

#[test]
fn placement_orders_partners_by_xor_distance_and_ids_are_content_derived() {
    let target = [0b1010_0000; 32];
    let mut c = vec![[0xFF; 32], [0b1010_0001; 32], [0x00; 32]];
    by_xor_distance(&mut c, &target);
    assert_eq!(c[0], [0b1010_0001; 32]);
    assert_eq!(
        stripe_id(&[[1; 32], [2; 32]]),
        stripe_id(&[[1; 32], [2; 32]])
    );
    assert_ne!(
        stripe_id(&[[1; 32], [2; 32]]),
        stripe_id(&[[2; 32], [1; 32]])
    );
}
