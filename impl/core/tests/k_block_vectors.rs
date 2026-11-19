//! Vecteurs et invariants pour `crypto.k-block` (Phase 0, spec V3).
//!
//! `K_block = KDF(master_key[version], "block", encryption_salt, u32(index))`
//! et trame de 65 536 o (docs/03-crypto/k-block.md). Valeurs attendues :
//! fichier généré par `cryptography` (jamais par le code testé).

use p2p_storage_core::k_block::{
    derive_k_block, open_block, seal_block, BLOCK_PLAINTEXT_LEN, BLOCK_SIZE,
};
use p2p_storage_core::symmetric_suite::hash_sha256;
use p2p_storage_core::CoreError;

include!("vectors/symmetric_suite_expected.rs");

fn arr<const N: usize>(h: &str) -> [u8; N] {
    hex::decode(h).unwrap().try_into().unwrap()
}

fn fixture_k_block() -> [u8; 32] {
    derive_k_block(
        &arr(FX_MASTER_KEY_HEX),
        &arr::<16>(FX_ENC_SALT_HEX),
        FX_BLOCK_INDEX,
    )
    .expect("K_block")
}

#[test]
fn k_block_matches_generated_vector() {
    assert_eq!(hex::encode(fixture_k_block()), K_BLOCK_HEX);
}

/// Une clé par position : deux index → deux clés.
#[test]
fn k_block_differs_per_block_index() {
    let (mk, salt) = (arr(FX_MASTER_KEY_HEX), arr::<16>(FX_ENC_SALT_HEX));
    assert_ne!(
        derive_k_block(&mk, &salt, 0).unwrap(),
        derive_k_block(&mk, &salt, 1).unwrap()
    );
}

/// Une clé par version d'élément : deux sels → deux clés.
#[test]
fn k_block_differs_per_encryption_salt() {
    let mk = arr(FX_MASTER_KEY_HEX);
    assert_ne!(
        derive_k_block(&mk, &[0xA0; 16], 0).unwrap(),
        derive_k_block(&mk, &[0xA1; 16], 0).unwrap()
    );
}

/// Rotation de `master_key` → nouvelles clés.
#[test]
fn k_block_differs_per_master_key_version() {
    let salt = arr::<16>(FX_ENC_SALT_HEX);
    assert_ne!(
        derive_k_block(&[0x10; 32], &salt, 0).unwrap(),
        derive_k_block(&[0x30; 32], &salt, 0).unwrap()
    );
}

#[test]
fn k_block_rejects_salt_of_wrong_length() {
    assert!(matches!(
        derive_k_block(&[0u8; 32], b"p2p-enc-salt-v1", 0),
        Err(CoreError::InvalidSaltLength {
            expected: 16,
            got: 15
        })
    ));
}

/// Trame exacte contre `cryptography` : 65 536 o, en-tête ‖ nonce ‖ chiffré ‖
/// tag, AAD = en-tête, clair complété par des zéros jusqu'à 65 506 o.
#[test]
fn block_frame_matches_generated_vector_and_is_65536_octets() {
    let frame = seal_block(
        &fixture_k_block(),
        &arr(FX_PROTO_HEADER_HEX),
        &arr(FX_BLOCK_NONCE_HEX),
        FX_BLOCK_PREFIX,
    )
    .expect("seal");
    assert_eq!(frame.len(), BLOCK_SIZE);
    assert_eq!(BLOCK_PLAINTEXT_LEN, 65_506);
    assert_eq!(hex::encode(hash_sha256(&frame)), BLOCK_FRAME_SHA256_HEX);
    assert_eq!(hex::encode(&frame[BLOCK_SIZE - 48..]), BLOCK_FRAME_TAIL_HEX);
    let clear = open_block(&fixture_k_block(), &arr(FX_PROTO_HEADER_HEX), &frame).expect("open");
    assert_eq!(&clear[..FX_BLOCK_PREFIX.len()], FX_BLOCK_PREFIX);
    assert!(clear[FX_BLOCK_PREFIX.len()..].iter().all(|&b| b == 0));
}

#[test]
fn block_rejects_oversized_plaintext_and_wrong_frame_size() {
    let k = fixture_k_block();
    let h = arr(FX_PROTO_HEADER_HEX);
    let too_big = vec![0u8; BLOCK_PLAINTEXT_LEN + 1];
    assert!(matches!(
        seal_block(&k, &h, &[0; 12], &too_big),
        Err(CoreError::BlockFormat { .. })
    ));
    assert!(matches!(
        open_block(&k, &h, &[0u8; 100]),
        Err(CoreError::BlockFormat { .. })
    ));
}

/// En-tête de version altéré (AAD) ou octet du chiffré altéré → rejet.
#[test]
fn block_tampering_is_rejected() {
    let k = fixture_k_block();
    let h = arr(FX_PROTO_HEADER_HEX);
    let frame = seal_block(&k, &h, &[7; 12], b"x").unwrap();
    assert!(matches!(
        open_block(&k, &[0, 2], &frame),
        Err(CoreError::BlockFormat { .. })
    ));
    let mut forged = frame.clone();
    forged[1] = 0x02;
    assert!(matches!(
        open_block(&k, &[0, 2], &forged),
        Err(CoreError::AeadFailure)
    ));
    let mut flipped = frame;
    flipped[100] ^= 1;
    assert!(matches!(
        open_block(&k, &h, &flipped),
        Err(CoreError::AeadFailure)
    ));
}
