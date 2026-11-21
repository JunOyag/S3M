//! Invariants de `protocols.espace-secours` (partie commune).

use s3m_protocol::emergency::*;
use s3m_protocol::exchange::*;

fn manifest(base: u8, ts: u64, root: u8, partner: u8) -> Manifest {
    let p = [partner; 32];
    Manifest {
        user_id: [1; 32],
        partners: vec![Partner {
            node_id: p,
            ip: "192.0.2.1".into(),
            port: 4001,
        }],
        blocks: vec![([root; 32], p)],
        roots: vec![RootChange {
            timestamp: ts,
            new_root: [root; 32],
            encryption_salt: [7; 16],
            key_version: 1,
        }],
        base_fs_root_hash: [base; 32],
        timestamp: ts,
    }
}

#[test]
fn manifest_roundtrips_through_the_signed_encrypted_entry() {
    let k = [9; 32];
    let m = manifest(2, 10, 3, 4);
    let env = emergency_entry_envelope(&k, 5, 10, &[1; 12], &m).unwrap();
    assert_eq!(open_emergency_entry(&k, &env).unwrap(), (5, m));
    // Une autre clé d'attachement ne déchiffre rien.
    assert!(open_emergency_entry(&[8; 32], &env).is_err());
    // L'enveloppe est acceptée par la règle DHT (signature de sig_pub_emergency).
    let key = s3m_protocol::dht::emergency_dht_key(&k);
    assert!(s3m_protocol::dht::accept_record(&key, &env, None, 10, &|_, _| Ok(false)).is_ok());
}

#[test]
fn merge_keeps_both_connectors_and_drops_a_stale_base() {
    let a = manifest(2, 10, 3, 4);
    let b = manifest(2, 20, 5, 6);
    let m = merge_manifest(Some(&a), &b);
    assert_eq!(m.partners.len(), 2);
    assert_eq!(m.blocks.len(), 2);
    assert_eq!(m.pending_root(&[2; 32]).unwrap().new_root, [5; 32]);
    assert_eq!(m.blocks_at(&[4; 32]), vec![[3; 32]]);
    assert!(
        m.pending_root(&[3; 32]).is_none(),
        "autre racine : rien à réconcilier"
    );
    // Entrée construite sur une autre racine : remplacée.
    let c = manifest(9, 30, 8, 4);
    assert_eq!(merge_manifest(Some(&m), &c), c);
}

#[test]
fn deposit_and_release_signatures_are_bound_to_their_inputs() {
    let sig_priv_user = [3; 32];
    let sig_pub_user = ed25519_dalek::SigningKey::from_bytes(&sig_priv_user)
        .verifying_key()
        .to_bytes();
    let keys = emergency_keys(&[9; 32]).unwrap();
    let s = emergency_deposit_signature(&sig_priv_user, &keys.sig_pub, b"me", b"partner");
    assert!(verify_emergency_deposit(
        &sig_pub_user,
        &keys.sig_pub,
        b"me",
        b"partner",
        &s
    ));
    assert!(!verify_emergency_deposit(
        &sig_pub_user,
        &keys.sig_pub,
        b"thief",
        b"partner",
        &s
    ));
    assert!(!verify_emergency_deposit(
        &sig_pub_user,
        &[0; 32],
        b"me",
        b"partner",
        &s
    ));

    let Body::EmergencyRelease {
        emergency_pub,
        timestamp,
        hashes,
        signature,
    } = emergency_release(&keys.sig_priv, 42, &[[1; 32], [2; 32]])
    else {
        panic!()
    };
    assert_eq!(emergency_pub, keys.sig_pub.to_vec());
    assert!(verify_emergency_release(
        &emergency_pub,
        timestamp,
        &hashes,
        &signature
    ));
    assert!(!verify_emergency_release(
        &emergency_pub,
        43,
        &hashes,
        &signature
    ));
    assert!(!verify_emergency_release(
        &emergency_pub,
        timestamp,
        &hashes[..32],
        &signature
    ));
}
