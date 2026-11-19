//! `network.dht-directory`, partie commune (component `protocol`, spec V3).
//! Vecteurs : `vectors/dht_expected.rs` (bibliothèque `cryptography`).
//! La VDF est remplacée par un double injecté (la vérification chiavdf réelle
//! est couverte par `impl/core`, tests `vdf_smoke` et `vdf_fixtures`).

use flatbuffers::FlatBufferBuilder;
use p2p_storage_core::vdf::VdfProof;
use p2p_storage_core::CoreError;
use p2p_storage_protocol::dht::*;
use p2p_storage_protocol::fb::dht as fb;

include!("vectors/dht_expected.rs");

fn arr<const N: usize>(h: &str) -> [u8; N] {
    hex::decode(h).unwrap().try_into().unwrap()
}

const SEED: [u8; 32] = [0x11; 32];
const NOW: u64 = 1_800_000_000;
const GOOD_Y: [u8; 100] = [1; 100];

/// Double de VDF : accepte une preuve dont `y` vaut `GOOD_Y`.
fn fake_vdf(_id: &[u8; 33], p: &VdfProof) -> Result<bool, CoreError> {
    Ok(p.y == GOOD_Y)
}

fn pub_of(seed: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes()
}

fn proof<'a>(
    fbb: &mut FlatBufferBuilder<'a>,
    tag: u8,
    key: &[u8; 32],
    y: [u8; 100],
) -> flatbuffers::WIPOffset<fb::VdfProof<'a>> {
    let mut id = vec![tag];
    id.extend_from_slice(key);
    let identity = fbb.create_vector(&id);
    let y = fbb.create_vector(&y);
    let pi = fbb.create_vector(&[2u8; 100]);
    fb::VdfProof::create(
        fbb,
        &fb::VdfProofArgs {
            identity: Some(identity),
            y: Some(y),
            pi: Some(pi),
        },
    )
}

fn user_payload(
    sig_pub: &[u8; 32],
    vdf_tag: u8,
    vdf_key: &[u8; 32],
    y: [u8; 100],
    ts: u64,
) -> Vec<u8> {
    let mut fbb = FlatBufferBuilder::new();
    let key = fbb.create_vector(sig_pub);
    let p = proof(&mut fbb, vdf_tag, vdf_key, y);
    let e = fb::UserEntry::create(
        &mut fbb,
        &fb::UserEntryArgs {
            sig_pub_user: Some(key),
            timestamp: ts,
            vdf_proof: Some(p),
            ciphertext: None,
        },
    );
    fb::finish_user_entry_buffer(&mut fbb, e);
    fbb.finished_data().to_vec()
}

fn emergency_payload(sig_pub: &[u8; 32], seq: u64) -> Vec<u8> {
    let mut fbb = FlatBufferBuilder::new();
    let key = fbb.create_vector(sig_pub);
    let e = fb::EmergencyEntry::create(
        &mut fbb,
        &fb::EmergencyEntryArgs {
            sig_pub_emergency: Some(key),
            seq,
            timestamp: NOW,
            ciphertext: None,
        },
    );
    fb::finish_emergency_entry_buffer(&mut fbb, e);
    fbb.finished_data().to_vec()
}

fn envelope_with_tag(tag: u8, payload: &[u8], sig: &[u8; 64]) -> Vec<u8> {
    let mut fbb = FlatBufferBuilder::new();
    let p = fbb.create_vector(payload);
    let s = fbb.create_vector(sig);
    let env = fb::DhtEnvelope::create(
        &mut fbb,
        &fb::DhtEnvelopeArgs {
            key_algorithm: tag,
            payload: Some(p),
            signature: Some(s),
        },
    );
    fbb.finish_minimal(env);
    fbb.finished_data().to_vec()
}

fn ctx() -> VerifyContext<'static> {
    VerifyContext {
        now: NOW,
        node_lookup_key: None,
        previous_seq: None,
    }
}

fn signed_user(payload: &[u8]) -> Vec<u8> {
    build_envelope(
        payload,
        &sign(&SEED, EntryKind::User.signature_label(), payload),
    )
}

// --- Vecteurs indépendants -------------------------------------------------

#[test]
fn signature_over_labelled_payload_matches_generated_vector() {
    let sig = sign(
        &arr(FX_SIG_SEED_HEX),
        "p2p-storage/sig/user-entry/v1",
        &hex::decode(FX_SIG_PAYLOAD_HEX).unwrap(),
    );
    assert_eq!(hex::encode(sig), SIGNATURE_HEX);
    assert_eq!(hex::encode(pub_of(&arr(FX_SIG_SEED_HEX))), SIG_PUB_HEX);
}

#[test]
fn blob_matches_generated_vector_and_is_bound_to_its_label() {
    let key = arr(FX_BLOB_KEY_HEX);
    let blob = seal_blob(
        &key,
        "dht-user-plaintext",
        &arr(FX_BLOB_NONCE_HEX),
        &hex::decode(FX_BLOB_PLAINTEXT_HEX).unwrap(),
    )
    .unwrap();
    assert_eq!(hex::encode(&blob), BLOB_HEX);
    assert_eq!(
        open_blob(&key, "dht-user-plaintext", &blob).unwrap(),
        hex::decode(FX_BLOB_PLAINTEXT_HEX).unwrap()
    );
    assert!(open_blob(&key, "dht-node-snapshot", &blob).is_err());
}

#[test]
fn lookup_keys_match_generated_vectors() {
    let k = arr(FX_K_ATTACH_HEX);
    assert_eq!(hex::encode(dispersal_dht_key(&k)), DISPERSAL_DHT_KEY_HEX);
    assert_eq!(hex::encode(emergency_dht_key(&k)), EMERGENCY_DHT_KEY_HEX);
}

#[test]
fn republish_smoothing_matches_generated_offset_and_unix_anchor() {
    let id = hex::decode(FX_OFFSET_ID_HEX).unwrap();
    assert_eq!(republish_offset(&id), OFFSET_S);
    let t = next_republish_at(&id, NOW);
    assert!((NOW..NOW + REPUBLISH_PERIOD_S).contains(&t));
    assert_eq!(t % REPUBLISH_PERIOD_S, OFFSET_S);
}

#[test]
fn ttl_constants_are_exact_seconds() {
    assert_eq!(TTL_SIX_MONTHS_S, 15_552_000);
    assert_eq!(ONE_YEAR_S, 31_536_000);
    assert_eq!(TTL_TEN_YEARS_S, 315_360_000);
    assert_eq!(REPUBLISH_PERIOD_S, 2_592_000);
    assert_eq!(EntryKind::User.ttl_seconds(), TTL_TEN_YEARS_S);
    for k in [EntryKind::Node, EntryKind::Dispersal, EntryKind::Emergency] {
        assert_eq!(k.ttl_seconds(), TTL_SIX_MONTHS_S);
    }
}

// --- Règles de vérification -----------------------------------------------

#[test]
fn valid_user_entry_verifies_and_returns_exact_payload_bytes() {
    let pk = pub_of(&SEED);
    let payload = user_payload(&pk, 0, &pk, GOOD_Y, NOW);
    let got = verify_envelope(&signed_user(&payload), EntryKind::User, &ctx(), &fake_vdf).unwrap();
    assert_eq!(got, payload);
}

#[test]
fn altered_payload_byte_is_rejected_as_bad_signature() {
    let pk = pub_of(&SEED);
    let payload = user_payload(&pk, 0, &pk, GOOD_Y, NOW);
    let sig = sign(&SEED, EntryKind::User.signature_label(), &payload);
    let mut altered = payload.clone();
    let last = altered.len() - 1;
    altered[last] ^= 1;
    let r = verify_envelope(
        &build_envelope(&altered, &sig),
        EntryKind::User,
        &ctx(),
        &fake_vdf,
    );
    assert!(matches!(
        r,
        Err(DhtError::BadSignature) | Err(DhtError::Format(_))
    ));
}

/// Séparation de contexte : une signature produite sous un autre libellé
/// (ex. Dispersal) par la même clé est rejetée pour une entrée User.
#[test]
fn signature_under_another_type_label_is_rejected() {
    let pk = pub_of(&SEED);
    let payload = user_payload(&pk, 0, &pk, GOOD_Y, NOW);
    let sig = sign(&SEED, EntryKind::Dispersal.signature_label(), &payload);
    let r = verify_envelope(
        &build_envelope(&payload, &sig),
        EntryKind::User,
        &ctx(),
        &fake_vdf,
    );
    assert!(matches!(r, Err(DhtError::BadSignature)));
}

#[test]
fn payload_of_another_type_is_rejected_by_file_identifier() {
    let pk = pub_of(&SEED);
    let payload = emergency_payload(&pk, 1);
    let r = verify_envelope(&signed_user(&payload), EntryKind::User, &ctx(), &fake_vdf);
    assert!(matches!(r, Err(DhtError::WrongFileIdentifier)));
}

#[test]
fn key_algorithm_tags_1_2_and_255_are_rejected_with_dedicated_errors() {
    let pk = pub_of(&SEED);
    let payload = user_payload(&pk, 0, &pk, GOOD_Y, NOW);
    let sig = sign(&SEED, EntryKind::User.signature_label(), &payload);
    for tag in [1u8, 2] {
        let r = verify_envelope(
            &envelope_with_tag(tag, &payload, &sig),
            EntryKind::User,
            &ctx(),
            &fake_vdf,
        );
        assert!(matches!(r, Err(DhtError::UnsupportedKeyAlgorithm(t)) if t == tag));
    }
    let r = verify_envelope(
        &envelope_with_tag(255, &payload, &sig),
        EntryKind::User,
        &ctx(),
        &fake_vdf,
    );
    assert!(matches!(r, Err(DhtError::UnknownKeyAlgorithm(255))));
    // Tag non supporté côté identité VDF, enveloppe en tag 0.
    let p1 = user_payload(&pk, 1, &pk, GOOD_Y, NOW);
    let r = verify_envelope(&signed_user(&p1), EntryKind::User, &ctx(), &fake_vdf);
    assert!(matches!(r, Err(DhtError::UnsupportedKeyAlgorithm(1))));
}

/// Preuve VDF User : porte sur `0x00 ‖ sig_pub_user` (❓2) ; autre clé ou
/// preuve refusée par le vérificateur → rejet.
#[test]
fn user_vdf_must_prove_sig_pub_user_and_be_valid() {
    let pk = pub_of(&SEED);
    let other = [0x77; 32];
    let wrong_key = user_payload(&pk, 0, &other, GOOD_Y, NOW);
    let r = verify_envelope(&signed_user(&wrong_key), EntryKind::User, &ctx(), &fake_vdf);
    assert!(matches!(r, Err(DhtError::InvalidVdf)));
    let bad_proof = user_payload(&pk, 0, &pk, [9; 100], NOW);
    let r = verify_envelope(&signed_user(&bad_proof), EntryKind::User, &ctx(), &fake_vdf);
    assert!(matches!(r, Err(DhtError::InvalidVdf)));
}

#[test]
fn expired_entry_is_rejected() {
    let pk = pub_of(&SEED);
    let old = NOW - TTL_TEN_YEARS_S - 1;
    let payload = user_payload(&pk, 0, &pk, GOOD_Y, old);
    let r = verify_envelope(&signed_user(&payload), EntryKind::User, &ctx(), &fake_vdf);
    assert!(matches!(r, Err(DhtError::Expired)));
}

/// `EmergencyEntry` : tout `seq` inférieur ou égal au `seq` détenu est rejeté.
#[test]
fn emergency_sequence_must_strictly_increase() {
    let pk = pub_of(&SEED);
    let label = EntryKind::Emergency.signature_label();
    let mk = |seq| {
        let p = emergency_payload(&pk, seq);
        build_envelope(&p, &sign(&SEED, label, &p))
    };
    let with_prev = |prev| VerifyContext {
        previous_seq: Some(prev),
        ..ctx()
    };
    assert!(verify_envelope(&mk(6), EntryKind::Emergency, &with_prev(5), &fake_vdf).is_ok());
    for seq in [5, 4] {
        let r = verify_envelope(&mk(seq), EntryKind::Emergency, &with_prev(5), &fake_vdf);
        assert!(matches!(r, Err(DhtError::StaleSequence)));
    }
}

/// `NodeEntry` : clé de vérification = clé de recherche `pub_node`.
#[test]
fn node_entry_is_verified_with_its_lookup_key() {
    let pk = pub_of(&SEED);
    let mut fbb = FlatBufferBuilder::new();
    let p = proof(&mut fbb, 0, &pk, GOOD_Y);
    let e = fb::NodeEntry::create(
        &mut fbb,
        &fb::NodeEntryArgs {
            timestamp: NOW,
            vdf_proof: Some(p),
            ..Default::default()
        },
    );
    fb::finish_node_entry_buffer(&mut fbb, e);
    let payload = fbb.finished_data().to_vec();
    let env = build_envelope(
        &payload,
        &sign(&SEED, EntryKind::Node.signature_label(), &payload),
    );
    let good = VerifyContext {
        node_lookup_key: Some(&pk),
        ..ctx()
    };
    assert!(verify_envelope(&env, EntryKind::Node, &good, &fake_vdf).is_ok());
    let other = pub_of(&[0x12; 32]);
    let bad = VerifyContext {
        node_lookup_key: Some(&other),
        ..ctx()
    };
    assert!(matches!(
        verify_envelope(&env, EntryKind::Node, &bad, &fake_vdf),
        Err(DhtError::BadSignature)
    ));
}

/// `migration_pointer` : signature `pub_node_recovery` sous son libellé,
/// `old_node_id` = nœud porteur, `seq` ≥ 1 et strictement croissant.
#[test]
fn migration_pointer_rules() {
    let recovery_seed = [0x21; 32];
    let recovery_pub = pub_of(&recovery_seed);
    let old_id = [0xA0; 32];
    let new_id = [0xB0; 32];
    let build = |old: [u8; 32], seq: u64, seed: [u8; 32]| {
        let mut fbb = FlatBufferBuilder::new();
        let o = fbb.create_vector(&old);
        let n = fbb.create_vector(&new_id);
        let p = fb::MigrationPointerPayload::create(
            &mut fbb,
            &fb::MigrationPointerPayloadArgs {
                old_node_id: Some(o),
                new_node_id: Some(n),
                seq,
                timestamp: NOW,
            },
        );
        fbb.finish_minimal(p);
        let payload = fbb.finished_data().to_vec();
        let sig = sign(&seed, SIG_LABEL_MIGRATION_POINTER, &payload);
        let mut fbb = FlatBufferBuilder::new();
        let pv = fbb.create_vector(&payload);
        let sv = fbb.create_vector(&sig);
        let smp = fb::SignedMigrationPointer::create(
            &mut fbb,
            &fb::SignedMigrationPointerArgs {
                payload: Some(pv),
                signature: Some(sv),
            },
        );
        fbb.finish_minimal(smp);
        fbb.finished_data().to_vec()
    };
    let check = |buf: &[u8], prev| {
        let smp = flatbuffers::root::<fb::SignedMigrationPointer>(buf).unwrap();
        verify_migration_pointer(smp, &recovery_pub, &old_id, prev)
    };
    assert_eq!(
        check(&build(old_id, 1, recovery_seed), None).unwrap(),
        new_id
    );
    assert!(matches!(
        check(&build([0xA1; 32], 1, recovery_seed), None),
        Err(DhtError::MigrationMismatch)
    ));
    assert!(matches!(
        check(&build(old_id, 2, recovery_seed), Some(2)),
        Err(DhtError::StaleSequence)
    ));
    assert!(matches!(
        check(&build(old_id, 0, recovery_seed), None),
        Err(DhtError::StaleSequence)
    ));
    assert!(matches!(
        check(&build(old_id, 1, [0x22; 32]), None),
        Err(DhtError::BadSignature)
    ));
}
