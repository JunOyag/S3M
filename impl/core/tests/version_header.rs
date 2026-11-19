//! Invariants de `deploiement.formats-serialisation`.

use p2p_storage_core::k_block::{derive_k_block, open_block, seal_block};
use p2p_storage_core::version::*;
use p2p_storage_core::CoreError;

#[test]
fn header_is_u16_big_endian_with_current_value_1() {
    assert_eq!(CURRENT_HEADER, [0x00, 0x01]);
    assert_eq!(encode_header(0x0102).unwrap(), [0x01, 0x02]);
    assert_eq!(parse_header(&[0x00, 0x01, 0xFF]).unwrap(), 1);
}

#[test]
fn reserved_zero_and_unknown_versions_are_rejected() {
    assert!(matches!(
        encode_header(0),
        Err(CoreError::InvalidVersionHeader { version: 0 })
    ));
    assert!(matches!(
        parse_header(&[0, 0]),
        Err(CoreError::InvalidVersionHeader { version: 0 })
    ));
    assert!(matches!(
        parse_header(&[0, 2]),
        Err(CoreError::InvalidVersionHeader { version: 2 })
    ));
    assert!(parse_header(&[1]).is_err());
}

/// L'en-tête est authentifié (AAD) : un même contenu sous une autre version
/// donne un autre chiffré, et un en-tête substitué fait échouer l'ouverture.
#[test]
fn version_is_authenticated_and_changes_the_ciphertext() {
    let k = derive_k_block(&[1; 32], &[2; 16], 0).unwrap();
    let v1 = seal_block(&k, &CURRENT_HEADER, &[3; 12], b"x").unwrap();
    let v2 = seal_block(&k, &encode_header(2).unwrap(), &[3; 12], b"x").unwrap();
    assert_ne!(v1[2..], v2[2..]);
    let mut swapped = v1.clone();
    swapped[..2].copy_from_slice(&[0, 2]);
    assert!(open_block(&k, &[0, 2], &swapped).is_err());
}
