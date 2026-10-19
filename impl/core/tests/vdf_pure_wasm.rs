//! Runtime WASM smoke test for the pure verifier. The fixture below is the
//! same Chia-format reference vector as the native unit test; its challenge
//! is raw `[0x42; 32]`, not a public-key identity and not an MPIR-generated
//! fixture. The public API hashes the provided identity, so this test verifies
//! that the same proof is rejected when bound to a different derived challenge.
#![cfg(target_arch = "wasm32")]

use p2p_storage_core::{
    vdf::{VdfProof, FORM_SIZE},
    vdf_pure::verify_legacy_identity_proof,
};
use wasm_bindgen_test::wasm_bindgen_test;
use web_time::Instant;

const PROOF_HEX: &str = "0300032167dfd0eb393ed5d544e6499ba24def860ecd8a3600490f2f87b003c3e7855763969d34e2d1c60910297df3aead9f078a1f4d3973903f532977f9639f693cdbd331e8ba96bd61c895726dd157d67310ae98d1632c9bb9f28e0d7337403c0a010004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

fn embedded_chia_reference_bytes() -> Vec<u8> {
    // This is copied byte-for-byte from the native test fixture; decode
    // directly so no suffix, padding, or other bytes can be introduced.
    let bytes = hex::decode(PROOF_HEX).expect("valid Chia reference-vector hex");
    assert_eq!(
        bytes.len(),
        FORM_SIZE * 2,
        "preserve the native reference vector"
    );
    bytes
}

#[wasm_bindgen_test]
fn executes_pure_verifier_on_embedded_chia_vector_for_wrong_identity() {
    let bytes = embedded_chia_reference_bytes();
    let proof = VdfProof {
        y: bytes[..FORM_SIZE].to_vec(),
        pi: bytes[FORM_SIZE..].to_vec(),
    };
    let started = Instant::now();
    let accepted = verify_legacy_identity_proof(&[0x42; 32], &proof)
        .expect("well-shaped proof must produce a verifier decision");
    let elapsed = started.elapsed();
    wasm_bindgen_test::console_log!("WASM pure VDF verifier duration: {elapsed:?}");

    // The embedded vector is for raw challenge [0x42; 32]. The identity API
    // hashes the key before deriving Δ, so it must not validate when that
    // raw challenge is incorrectly supplied as a public key. This exercises
    // the real verifier path without exposing a raw-challenge API.
    assert!(!accepted);
}
