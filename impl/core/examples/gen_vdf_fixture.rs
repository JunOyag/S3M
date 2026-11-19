//! Génère la fixture VDF `T = 1000` de `network.vdf-verifier-pure` avec
//! `chiavdf` (seul prouveur du protocole). Sortie : hex de `y ‖ π` (200 o)
//! pour l'identité marquée `0x00 ‖ [0x31; 32]`.
//!
//! Usage (outillage chiavdf requis, par ex. sous Docker) :
//!     cargo run --release --features vdf --example gen_vdf_fixture
//! Consigner la provenance dans tests/fixtures/vdf_identity_tag0_t1000.provenance.

use p2p_storage_core::vdf::{
    generate_identity_proof_params, tagged_identity, KEY_ALGORITHM_ED25519,
};

fn main() {
    let identity = tagged_identity(KEY_ALGORITHM_ED25519, &[0x31; 32]).expect("tag 0");
    let proof = generate_identity_proof_params(&identity, 1000).expect("chiavdf::prove");
    let mut blob = proof.y.clone();
    blob.extend_from_slice(&proof.pi);
    println!("{}", hex_encode(&blob));
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
