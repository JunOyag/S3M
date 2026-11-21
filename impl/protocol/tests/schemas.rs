//! Types FlatBuffers générés (Phase 1) — aller-retour des racines et
//! invariants de schéma explicites des pages `docs/02-schemas/**`.

use flatbuffers::FlatBufferBuilder;
use s3m_protocol::fb::{dht, dispersal, emergency, fs, node};

/// Les quatre entrées DHT portent chacune leur `file_identifier`
/// (`NODE`, `USER`, `DISP`, `EMRG`, `ALRT`) : un payload n'est jamais décodé sous
/// un mauvais type (page network.dht-directory).
#[test]
fn dht_entries_carry_distinct_file_identifiers() {
    let mut fbb = FlatBufferBuilder::new();
    let key = fbb.create_vector(&[7u8; 32]);
    let root = dht::DispersalEntry::create(
        &mut fbb,
        &dht::DispersalEntryArgs {
            sig_pub_dispersal: Some(key),
            timestamp: 42,
            ciphertext: None,
        },
    );
    dht::finish_dispersal_entry_buffer(&mut fbb, root);
    let buf = fbb.finished_data();
    assert!(dht::dispersal_entry_buffer_has_identifier(buf));
    assert!(!dht::node_entry_buffer_has_identifier(buf));
    assert!(!dht::user_entry_buffer_has_identifier(buf));
    assert!(!dht::emergency_entry_buffer_has_identifier(buf));
    let entry = dht::root_as_dispersal_entry(buf).expect("verify");
    assert_eq!(entry.timestamp(), 42);
    assert_eq!(entry.sig_pub_dispersal().unwrap().bytes(), &[7u8; 32]);
    assert_eq!(
        [
            dht::NODE_ENTRY_IDENTIFIER,
            dht::USER_ENTRY_IDENTIFIER,
            dht::DISPERSAL_ENTRY_IDENTIFIER,
            dht::EMERGENCY_ENTRY_IDENTIFIER,
            dht::ALERT_ENTRY_IDENTIFIER
        ],
        ["NODE", "USER", "DISP", "EMRG", "ALRT"]
    );
}

/// `NodeEntry` : preuve VDF (identité marquée 33 o, y et π de 100 o) et
/// pointeur de migration signé imbriqués.
#[test]
fn node_entry_roundtrips_with_vdf_proof_and_migration_pointer() {
    let mut fbb = FlatBufferBuilder::new();
    let identity = fbb.create_vector(&[0u8; 33]);
    let y = fbb.create_vector(&[1u8; 100]);
    let pi = fbb.create_vector(&[2u8; 100]);
    let proof = dht::VdfProof::create(
        &mut fbb,
        &dht::VdfProofArgs {
            identity: Some(identity),
            y: Some(y),
            pi: Some(pi),
        },
    );
    let mp_payload = fbb.create_vector(&[3u8; 10]);
    let mp_sig = fbb.create_vector(&[4u8; 64]);
    let mp = dht::SignedMigrationPointer::create(
        &mut fbb,
        &dht::SignedMigrationPointerArgs {
            payload: Some(mp_payload),
            signature: Some(mp_sig),
        },
    );
    let ip = fbb.create_string("192.0.2.1");
    let root = dht::NodeEntry::create(
        &mut fbb,
        &dht::NodeEntryArgs {
            ip: Some(ip),
            port: 4001,
            timestamp: 1,
            vdf_proof: Some(proof),
            pub_node_recovery: None,
            migration_pointer: Some(mp),
            snapshot_ciphertext: None,
            addrs: None,
            pub_node_announce: None,
            name: None,
        },
    );
    dht::finish_node_entry_buffer(&mut fbb, root);
    let e = dht::root_as_node_entry(fbb.finished_data()).expect("verify");
    assert_eq!(e.ip(), Some("192.0.2.1"));
    assert_eq!(e.port(), 4001);
    let p = e.vdf_proof().unwrap();
    assert_eq!(p.identity().unwrap().len(), 33);
    assert_eq!(p.pi().unwrap().len(), 100);
    assert_eq!(
        e.migration_pointer().unwrap().signature().unwrap().len(),
        64
    );
}

/// `Stripe.encryption_salt` (V3) : sel de l'`IndexNode` enfant porté par
/// le parent ; `DispersalRootPointer.dispersal_root_salt` pour la racine.
#[test]
fn index_node_salts_are_carried_by_parent_stripe_and_root_pointer() {
    let mut fbb = FlatBufferBuilder::new();
    let salt = fbb.create_vector(&[9u8; 16]);
    let stripe = dispersal::Stripe::create(
        &mut fbb,
        &dispersal::StripeArgs {
            stripe_id: None,
            k: 4,
            m: 16,
            blocks: None,
            encryption_salt: Some(salt),
        },
    );
    let children = fbb.create_vector(&[stripe]);
    let root_node = dispersal::IndexNode::create(
        &mut fbb,
        &dispersal::IndexNodeArgs {
            is_leaf: false,
            stripes: None,
            children: Some(children),
        },
    );
    let manifest = dispersal::DispersalManifest::create(
        &mut fbb,
        &dispersal::DispersalManifestArgs {
            user_id: None,
            node_id: None,
            partners: None,
            root: Some(root_node),
            timestamp: 5,
        },
    );
    dispersal::finish_dispersal_manifest_buffer(&mut fbb, manifest);
    let m = dispersal::root_as_dispersal_manifest(fbb.finished_data()).expect("verify");
    let child = m.root().unwrap().children().unwrap().get(0);
    assert_eq!(child.encryption_salt().unwrap().bytes(), &[9u8; 16]);

    let mut fbb = FlatBufferBuilder::new();
    let root_salt = fbb.create_vector(&[8u8; 16]);
    let ptr = dht::DispersalRootPointer::create(
        &mut fbb,
        &dht::DispersalRootPointerArgs {
            dispersal_root_hash: None,
            dispersal_root_partners: None,
            dispersal_root_salt: Some(root_salt),
            dispersal_root_stripe: None,
        },
    );
    fbb.finish_minimal(ptr);
    let p = flatbuffers::root::<dht::DispersalRootPointer>(fbb.finished_data()).expect("verify");
    assert_eq!(p.dispersal_root_salt().unwrap().len(), 16);
}

/// `blocks_to_delete` : hash SHA-256 de 32 o concaténés (pas de vecteur de
/// vecteurs en FlatBuffers) ; `EmergencyEntry.seq` en clair.
#[test]
fn write_queue_and_emergency_roundtrip() {
    let mut fbb = FlatBufferBuilder::new();
    let chain = fbb.create_vector(&[0xAAu8; 64]);
    let op = fbb.create_string("delete_entry");
    let mutation = fs::QueuedMutation::create(
        &mut fbb,
        &fs::QueuedMutationArgs {
            timestamp: 3,
            op: Some(op),
            blocks_to_delete: Some(chain),
            ..Default::default()
        },
    );
    let mutations = fbb.create_vector(&[mutation]);
    let wq = fs::WriteQueue::create(
        &mut fbb,
        &fs::WriteQueueArgs {
            base_fs_root_hash: None,
            mutations: Some(mutations),
        },
    );
    fs::finish_write_queue_buffer(&mut fbb, wq);
    let q = fs::root_as_write_queue(fbb.finished_data()).expect("verify");
    let blocks = q.mutations().unwrap().get(0).blocks_to_delete().unwrap();
    assert_eq!(blocks.len() % 32, 0);
    assert_eq!(blocks.len() / 32, 2);

    let mut fbb = FlatBufferBuilder::new();
    let e = dht::EmergencyEntry::create(
        &mut fbb,
        &dht::EmergencyEntryArgs {
            sig_pub_emergency: None,
            seq: 7,
            timestamp: 9,
            ciphertext: None,
        },
    );
    dht::finish_emergency_entry_buffer(&mut fbb, e);
    let r = dht::root_as_emergency_entry(fbb.finished_data()).expect("verify");
    assert_eq!(r.seq(), 7);

    let mut fbb = FlatBufferBuilder::new();
    let em = emergency::EmergencyManifest::create(&mut fbb, &Default::default());
    emergency::finish_emergency_manifest_buffer(&mut fbb, em);
    assert!(emergency::root_as_emergency_manifest(fbb.finished_data()).is_ok());
}

/// `MutationLog` : union de payloads, dont un `BlockEntry` du namespace
/// Dispersal ; `NodeManifest` minimal.
#[test]
fn node_mutation_log_union_and_manifest_roundtrip() {
    let mut fbb = FlatBufferBuilder::new();
    let hash = fbb.create_vector(&[1u8; 32]);
    let block = dispersal::BlockEntry::create(
        &mut fbb,
        &dispersal::BlockEntryArgs {
            block_hash: Some(hash),
            block_index: 2,
            ..Default::default()
        },
    );
    let op = fbb.create_string("add_block");
    let m = node::Mutation::create(
        &mut fbb,
        &node::MutationArgs {
            timestamp: 1,
            op: Some(op),
            payload_type: node::MutationPayload::S3m_Dispersal_BlockEntry,
            payload: Some(block.as_union_value()),
        },
    );
    let ms = fbb.create_vector(&[m]);
    let log = node::MutationLog::create(
        &mut fbb,
        &node::MutationLogArgs {
            mutations: Some(ms),
        },
    );
    node::finish_mutation_log_buffer(&mut fbb, log);
    let l = node::root_as_mutation_log(fbb.finished_data()).expect("verify");
    let entry = l
        .mutations()
        .unwrap()
        .get(0)
        .payload_as_s3m_dispersal_block_entry()
        .expect("BlockEntry");
    assert_eq!(entry.block_index(), 2);

    let mut fbb = FlatBufferBuilder::new();
    let nm = node::NodeManifest::create(&mut fbb, &Default::default());
    node::finish_node_manifest_buffer(&mut fbb, nm);
    assert!(node::root_as_node_manifest(fbb.finished_data()).is_ok());
}

/// Un buffer tronqué est rejeté par le vérificateur FlatBuffers (entrée
/// non fiable venant d'un pair).
#[test]
fn truncated_buffer_is_rejected_by_verifier() {
    let mut fbb = FlatBufferBuilder::new();
    let key = fbb.create_vector(&[7u8; 32]);
    let root = dht::UserEntry::create(
        &mut fbb,
        &dht::UserEntryArgs {
            sig_pub_user: Some(key),
            ..Default::default()
        },
    );
    dht::finish_user_entry_buffer(&mut fbb, root);
    let buf = fbb.finished_data();
    assert!(dht::root_as_user_entry(&buf[..buf.len() - 8]).is_err());
}

/// Chacune des 41 tables générées se construit, passe le vérificateur et
/// se relit (couverture minimale de tout le code généré).
#[test]
fn every_generated_table_builds_and_verifies() {
    macro_rules! check {
        ($($t:ident :: $n:ident),* $(,)?) => {$({
            let mut fbb = FlatBufferBuilder::new();
            let root = $t::$n::create(&mut fbb, &Default::default());
            fbb.finish_minimal(root);
            flatbuffers::root::<$t::$n>(fbb.finished_data())
                .unwrap_or_else(|e| panic!("{}: {e}", stringify!($n)));
        })*};
    }
    check!(
        dispersal::BlockEntry,
        dispersal::DispersalManifest,
        dispersal::IndexNode,
        dispersal::MasterKeyEntry,
        dispersal::Partner,
        dispersal::Stripe,
        emergency::EmergencyBlockEntry,
        emergency::EmergencyManifest,
        emergency::EmergencyMutation,
        emergency::EmergencyPartner,
        fs::Attributes,
        fs::DirectoryBlock,
        fs::DirectoryEntry,
        fs::FileBlock,
        fs::Metadata,
        fs::QueuedMutation,
        fs::WriteQueue,
        dht::AttachmentRecord,
        dht::DhtEnvelope,
        dht::DispersalEntry,
        dht::DispersalRootPointer,
        dht::EmergencyEntry,
        dht::MigrationPointerPayload,
        dht::NodeEntry,
        dht::NodeSnapshotPointer,
        dht::SignedMigrationPointer,
        dht::UserEntry,
        dht::UserEntryPlaintext,
        dht::VdfProof,
        node::AttachedUser,
        node::BlacklistedPartner,
        node::BlockLocation,
        node::ContainerFile,
        node::Mutation,
        node::MutationLog,
        node::NodeConfig,
        node::NodeManifest,
        node::PartnerAccount,
        node::StripeRemoval,
        node::UserQuota,
        node::VolumeConfig
    );
}
