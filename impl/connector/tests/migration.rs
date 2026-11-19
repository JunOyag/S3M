//! `protocols.migration-noeud` de bout en bout : ancien Nœud, Connecteur,
//! nouveau Nœud.

use flatbuffers::FlatBufferBuilder;
use p2p_storage_connector::migration::prepare_handoff;
use p2p_storage_core::erasure::encode_parity;
use p2p_storage_core::k_attach::{
    derive_k_attach_as_node, derive_k_attach_as_user, derive_sig_priv_dispersal,
};
use p2p_storage_core::k_dispersal::derive_k_dispersal_content;
use p2p_storage_node::migration::{new_sig_priv_dispersal, rebuild_stripe};
use p2p_storage_protocol::dht::{build_envelope, seal_blob, sign, EntryKind};
use p2p_storage_protocol::fb::{dht as fbd, dispersal as fbs};
use p2p_storage_protocol::index::{open_index_node, seal_index_node};

fn pubkey(seed: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes()
}

const USER: [u8; 32] = [0x61; 32];
const OLD_NODE: [u8; 32] = [0x71; 32];
const NEW_NODE: [u8; 32] = [0x72; 32];

/// Entrée DHT de l'ancien Nœud : pointeur racine chiffré sous l'ancien K_attach.
fn old_dispersal_envelope(k_attach: &[u8; 32]) -> Vec<u8> {
    let mut fbb = FlatBufferBuilder::new();
    let nid = fbb.create_vector(&[0xAAu8; 32]);
    let ip = fbb.create_string("192.0.2.20");
    let p = fbs::Partner::create(
        &mut fbb,
        &fbs::PartnerArgs {
            partner_id: 7,
            node_id: Some(nid),
            ip: Some(ip),
            port: 4001,
        },
    );
    let partners = fbb.create_vector(&[p]);
    let root = fbb.create_vector(&[0xBBu8; 32]);
    let salt = fbb.create_vector(&[0xCCu8; 16]);
    let ptr = fbd::DispersalRootPointer::create(
        &mut fbb,
        &fbd::DispersalRootPointerArgs {
            dispersal_root_hash: Some(root),
            dispersal_root_partners: Some(partners),
            dispersal_root_salt: Some(salt),
        },
    );
    fbb.finish_minimal(ptr);
    let clear = fbb.finished_data().to_vec();
    let blob = seal_blob(
        k_attach,
        EntryKind::Dispersal.blob_aad_label(),
        &[1; 12],
        &clear,
    )
    .unwrap();
    let sig_seed = derive_sig_priv_dispersal(k_attach).unwrap();
    let mut fbb = FlatBufferBuilder::new();
    let key = fbb.create_vector(&pubkey(&sig_seed));
    let ct = fbb.create_vector(&blob);
    let e = fbd::DispersalEntry::create(
        &mut fbb,
        &fbd::DispersalEntryArgs {
            sig_pub_dispersal: Some(key),
            timestamp: 1,
            ciphertext: Some(ct),
        },
    );
    fbd::finish_dispersal_entry_buffer(&mut fbb, e);
    let payload = fbb.finished_data().to_vec();
    build_envelope(
        &payload,
        &sign(&sig_seed, EntryKind::Dispersal.signature_label(), &payload),
    )
}

#[test]
fn connector_hands_off_root_and_content_key_but_never_k_attach() {
    let old_salt = [0x11; 16];
    let old_k_attach = derive_k_attach_as_node(&OLD_NODE, &pubkey(&USER), &old_salt).unwrap();
    assert_eq!(
        old_k_attach,
        derive_k_attach_as_user(&USER, &pubkey(&OLD_NODE), &old_salt).unwrap()
    );
    let env = old_dispersal_envelope(&old_k_attach);

    let h = prepare_handoff(&USER, &pubkey(&OLD_NODE), &old_salt, &env).unwrap();
    assert_eq!(h.dispersal_root_hash, vec![0xBB; 32]);
    assert_eq!(
        h.root_partners,
        vec![(7, vec![0xAA; 32], "192.0.2.20".into(), 4001)]
    );
    assert_eq!(h.dispersal_root_salt, vec![0xCC; 16]);
    assert_eq!(
        h.k_dispersal_content,
        derive_k_dispersal_content(&old_k_attach).unwrap()
    );
    // Le transfert ne contient ni K_attach ni la graine de signature.
    let sig = derive_sig_priv_dispersal(&old_k_attach).unwrap();
    let dump = format!("{h:?}");
    assert!(!dump.contains(&format!("{:?}", old_k_attach)));
    assert!(!dump.contains(&format!("{sig:?}")));

    // Le nouveau Nœud déchiffre seul le nœud d'index racine.
    let root_bytes = b"index racine".to_vec();
    let salt: [u8; 16] = h.dispersal_root_salt.clone().try_into().unwrap();
    let frame = seal_index_node(
        &h.k_dispersal_content,
        &salt,
        &[0, 1],
        &[2; 12],
        &root_bytes,
    )
    .unwrap();
    let clear = open_index_node(&h.k_dispersal_content, &salt, &[0, 1], &frame).unwrap();
    assert_eq!(&clear[..root_bytes.len()], root_bytes.as_slice());
}

/// Le nouveau Nœud reconstruit chaque stripe depuis k fragments de parité,
/// recalcule une nouvelle parité, et signe sous une sig_pub_dispersal neuve.
#[test]
fn new_node_rebuilds_from_parity_and_signs_with_its_own_key() {
    let data: Vec<Vec<u8>> = (0..4).map(|i| vec![i as u8 * 3; 2048]).collect();
    let refs: Vec<&[u8]> = data.iter().map(|d| d.as_slice()).collect();
    let parity = encode_parity(&refs, 3).unwrap();
    let fetched: Vec<Option<Vec<u8>>> = parity
        .iter()
        .enumerate()
        .map(|(i, p)| [1, 4, 6, 11].contains(&i).then(|| p.clone()))
        .collect();
    let (rebuilt, new_parity) = rebuild_stripe(fetched, 4, 3).unwrap();
    assert_eq!(rebuilt, data);
    assert_eq!(new_parity, parity);

    let old_salt = [0x11; 16];
    let new_salt = [0x22; 16];
    let old_sig = derive_sig_priv_dispersal(
        &derive_k_attach_as_node(&OLD_NODE, &pubkey(&USER), &old_salt).unwrap(),
    )
    .unwrap();
    let new_sig = new_sig_priv_dispersal(&NEW_NODE, &pubkey(&USER), &new_salt).unwrap();
    assert_ne!(old_sig, new_sig);
}
