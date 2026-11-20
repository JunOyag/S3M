//! Conformité des fixtures VDF — id `network.vdf-verifier-pure`
//! (« Instrumentation et fixtures VDF », spec V3).
//!
//! Quatre critères de la page : natif (fixture acceptée par chiavdf),
//! accord (prove régénéré = fixture octet pour octet), rejets (y, π,
//! identité, T), traçabilité (provenance versionnée). Plus une mesure par
//! phase, imprimée avec `--nocapture`.
#![cfg(feature = "vdf")]

use std::time::Instant;

use s3m_core::vdf::{
    generate_identity_proof_params, tagged_identity, verify_identity_proof_params, VdfProof,
    FORM_SIZE, KEY_ALGORITHM_ED25519, TAGGED_IDENTITY_LEN,
};

const FIXTURE: &str = include_str!("fixtures/vdf_identity_tag0_t1000.hex");
const PROVENANCE: &str = include_str!("fixtures/vdf_identity_tag0_t1000.provenance");
const FIXTURE_T: u64 = 1000;

fn identity() -> [u8; TAGGED_IDENTITY_LEN] {
    tagged_identity(KEY_ALGORITHM_ED25519, &[0x31; 32]).expect("tag 0")
}

fn fixture_proof() -> VdfProof {
    let blob = hex::decode(FIXTURE.trim()).expect("hex");
    assert_eq!(blob.len(), 2 * FORM_SIZE);
    VdfProof {
        y: blob[..FORM_SIZE].to_vec(),
        pi: blob[FORM_SIZE..].to_vec(),
    }
}

fn verify(id: &[u8; TAGGED_IDENTITY_LEN], proof: &VdfProof, t: u64) -> bool {
    verify_identity_proof_params(id, proof, t, 0).expect("vérification")
}

#[test]
fn fixture_is_accepted_natively() {
    assert!(verify(&identity(), &fixture_proof(), FIXTURE_T));
}

#[test]
fn regenerated_proof_matches_fixture_byte_for_byte() {
    let proof = generate_identity_proof_params(&identity(), FIXTURE_T).expect("prove");
    let expected = fixture_proof();
    assert_eq!(proof.y, expected.y);
    assert_eq!(proof.pi, expected.pi);
}

#[test]
fn fixture_mutations_are_rejected() {
    let id = identity();
    let mut y = fixture_proof();
    y.y[10] ^= 1;
    assert!(!verify(&id, &y, FIXTURE_T));
    let mut pi = fixture_proof();
    pi.pi[10] ^= 1;
    assert!(!verify(&id, &pi, FIXTURE_T));
    let mut other_key = id;
    other_key[1] ^= 1;
    assert!(!verify(&other_key, &fixture_proof(), FIXTURE_T));
    assert!(!verify(&id, &fixture_proof(), FIXTURE_T + 1));
}

#[test]
fn fixture_provenance_is_recorded() {
    for field in [
        "identite: 0x00 || [0x31; 32]",
        "T=1000",
        "chiavdf 1.1.14",
        "commande:",
    ] {
        assert!(PROVENANCE.contains(field), "provenance sans « {field} »");
    }
}

/// Mesure par phase (page § « Instrumentation par phase ») : `prove`
/// (mise en groupe, évaluation et preuve, non séparables depuis l'API
/// publique) et vérification (recalcul de Δ compris).
#[test]
fn phase_timings_are_reported() {
    let id = identity();
    let start = Instant::now();
    let proof = generate_identity_proof_params(&id, FIXTURE_T).expect("prove");
    let prove = start.elapsed();
    let start = Instant::now();
    assert!(verify(&id, &proof, FIXTURE_T));
    let verify_time = start.elapsed();
    println!("[vdf T={FIXTURE_T}] prove={prove:?} verify={verify_time:?}");
}
