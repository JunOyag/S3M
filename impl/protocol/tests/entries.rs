//! Construction des entrées DHT Node et User (`network.dht-directory`).

use s3m_core::vdf::VdfProof;
use s3m_protocol::dht::accept_record;
use s3m_protocol::entries::*;

fn pk(s: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(s)
        .verifying_key()
        .to_bytes()
}

fn proof() -> VdfProof {
    VdfProof {
        y: vec![1; 100],
        pi: vec![2; 100],
    }
}

#[test]
fn proof_cache_roundtrips() {
    let p = proof();
    let back = decode_proof(&encode_proof(&p)).unwrap();
    assert_eq!((back.y, back.pi), (p.y, p.pi));
    assert!(decode_proof(&[0]).is_none());
}

/// L'entrée Node est acceptée sous `pub_node` ; la VDF est vérifiée sur
/// `0x00 ‖ pub_node`.
#[test]
fn node_entry_is_accepted_with_proof_on_tagged_pub_node() {
    let seed = [5u8; 32];
    let env = node_entry_envelope(
        &seed,
        &NodeEntryParams {
            ip: "203.0.113.7",
            port: 4002,
            timestamp: 1_000,
            proof: &proof(),
            pub_node_recovery: &pk(&[6; 32]),
            snapshot_pointer: Some(b"pointeur"),
            addrs: &[],
            pub_node_announce: None,
            name: Some(" Nœud	de Paul "),
        },
        &[1; 12],
    )
    .unwrap();
    assert_eq!(node_entry_name(&env).as_deref(), Some("Nœudde Paul"));
    let want = node_identity(&pk(&seed)).unwrap();
    let ok = accept_record(&pk(&seed), &env, None, 1_000, &|id, _| Ok(*id == want));
    assert!(ok.is_ok(), "{ok:?}");
    assert!(accept_record(&pk(&seed), &env, None, 1_000, &|_, _| Ok(false)).is_err());
    let (addrs, direct) = node_entry_addrs(&env).unwrap();
    assert!(addrs.is_empty());
    assert_eq!(direct, Some(("203.0.113.7".to_string(), 4002)));
    let relayed =
        vec!["/ip4/198.51.100.1/tcp/4002/p2p/12D3KooWRelay/p2p-circuit/p2p/12D3KooWMe".to_string()];
    let env = node_entry_envelope(
        &seed,
        &NodeEntryParams {
            ip: "",
            port: 0,
            timestamp: 1_001,
            proof: &proof(),
            pub_node_recovery: &pk(&[6; 32]),
            snapshot_pointer: None,
            addrs: &relayed,
            pub_node_announce: None,
            name: None,
        },
        &[1; 12],
    )
    .unwrap();
    assert_eq!(
        node_entry_addrs(&env).unwrap(),
        (relayed, None),
        "Nœud derrière un NAT"
    );
}

#[test]
fn user_entry_is_accepted_and_opens_with_the_user_key_only() {
    let (priv_user, pub_user) = ([7u8; 32], pk(&[7u8; 32]));
    let plain = UserPlain {
        fs_root_hash: [9; 32],
        encryption_salt: [3; 16],
        key_version: 1,
        attachments: vec![Attachment {
            node_id: [4; 32],
            salt: vec![5; 16],
            timestamp: 10,
            inactivity_detected_at: 0,
            node_label: "Maison".into(),
        }],
        pseudo: "Perso".into(),
        devices: vec![DeviceRec { device_id: [1; 16], peer_id: vec![2; 38], name: "PC bureau".into(), added_at: 5, updated_at: 6, deleted: false }],
    };
    let (key, env) =
        user_entry_envelope(&priv_user, &pub_user, 1_000, &proof(), &plain, &[2; 12]).unwrap();
    let want = user_identity(&priv_user, &pub_user).unwrap();
    assert!(accept_record(&key, &env, None, 1_000, &|id, _| Ok(*id == want)).is_ok());
    assert_eq!(open_user_entry(&priv_user, &env).unwrap(), plain);
    assert!(open_user_entry(&[8; 32], &env).is_err());
}

#[test]
fn device_lists_merge_by_latest_change() {
    let d = |id: u8, name: &str, at: u64| DeviceRec { device_id: [id; 16], name: name.into(), updated_at: at, added_at: id as u64, ..Default::default() };
    let m = merge_devices(&[d(1, "ancien", 1), d(2, "B", 5)], &[d(1, "PC", 3), d(3, "C", 2)]);
    assert_eq!(m.iter().map(|x| x.name.as_str()).collect::<Vec<_>>(), vec!["PC", "B", "C"]);
    let many: Vec<_> = (0..40).map(|i| d(i, "x", i as u64)).collect();
    assert_eq!(merge_devices(&many, &[]).len(), MAX_DEVICES);
}
