//! `deploiement.disaster-recovery` (partie node) : restauration depuis la
//! seule seed « Node ».

use flatbuffers::FlatBufferBuilder;
use p2p_storage_core::identity_derivation::{derive_identity_seed, mnemonic_to_seed, IdentityRole};
use p2p_storage_core::k_attach::derive_k_attach_as_user;
use p2p_storage_core::k_node_self::derive_k_node_self;
use p2p_storage_node::restore::*;
use p2p_storage_protocol::dht::{build_envelope, dispersal_dht_key, seal_blob, sign, EntryKind};
use p2p_storage_protocol::fb::{dht as fb, dispersal as fbs};

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn pubk(s: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(s)
        .verifying_key()
        .to_bytes()
}

/// Entrée Node publiée avant le sinistre, avec son pointeur de snapshot.
fn published_node_entry(priv_node: &[u8; 32]) -> Vec<u8> {
    let mut fbb = FlatBufferBuilder::new();
    let id = fbb.create_vector(&[0x51u8; 32]);
    let p = fbs::Partner::create(
        &mut fbb,
        &fbs::PartnerArgs {
            partner_id: 3,
            node_id: Some(id),
            ..Default::default()
        },
    );
    let partners = fbb.create_vector(&[p]);
    let root = fbb.create_vector(&[0x52u8; 32]);
    let ptr = fb::NodeSnapshotPointer::create(
        &mut fbb,
        &fb::NodeSnapshotPointerArgs {
            node_snapshot_root_hash: Some(root),
            node_snapshot_root_partners: Some(partners),
        },
    );
    fbb.finish_minimal(ptr);
    let clear = fbb.finished_data().to_vec();
    let blob = seal_blob(
        &derive_k_node_self(priv_node).unwrap(),
        EntryKind::Node.blob_aad_label(),
        &[4; 12],
        &clear,
    )
    .unwrap();
    let mut fbb = FlatBufferBuilder::new();
    let ct = fbb.create_vector(&blob);
    let e = fb::NodeEntry::create(
        &mut fbb,
        &fb::NodeEntryArgs {
            timestamp: 1,
            snapshot_ciphertext: Some(ct),
            ..Default::default()
        },
    );
    fb::finish_node_entry_buffer(&mut fbb, e);
    let payload = fbb.finished_data().to_vec();
    build_envelope(
        &payload,
        &sign(priv_node, EntryKind::Node.signature_label(), &payload),
    )
}

#[test]
fn node_restores_snapshot_pointer_and_user_keys_from_seed_alone() {
    let seed = mnemonic_to_seed(MNEMONIC, "").unwrap();
    let priv_node = derive_identity_seed(&seed, IdentityRole::Node, 0).unwrap();
    let env = published_node_entry(&priv_node);

    // « Nouvelle machine » : seule la seed est connue.
    let restored = derive_identity_seed(
        &mnemonic_to_seed(MNEMONIC, "").unwrap(),
        IdentityRole::Node,
        0,
    )
    .unwrap();
    let ptr = snapshot_pointer(&restored, &env).unwrap();
    assert_eq!(ptr.root_hash, vec![0x52; 32]);
    assert_eq!(ptr.partners, vec![(3, vec![0x51; 32])]);
    assert!(
        snapshot_pointer(&[0x01; 32], &env).is_err(),
        "autre seed : illisible"
    );

    // Étape 4 : K_attach recalculé côté Nœud = celui du User.
    let priv_user = [0x61; 32];
    let salt = [0x11; 16];
    let (k, dht_key) = attached_user_keys(&restored, &pubk(&priv_user), &salt).unwrap();
    assert_eq!(
        k,
        derive_k_attach_as_user(&priv_user, &pubk(&restored), &salt).unwrap()
    );
    assert_eq!(dht_key, dispersal_dht_key(&k));
}
