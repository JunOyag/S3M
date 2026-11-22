//! Base32 RFC 4648 (secret 2FA, `deploiement.appairage-admin`) et registre
//! KDF `"admin-totp"`.

use s3m_core::identity_derivation::{base32_decode, base32_encode};
use s3m_core::symmetric_suite::derive_admin_totp_secret;

#[test]
fn base32_matches_rfc4648_vectors() {
    for (raw, enc) in [
        ("", ""),
        ("f", "MY"),
        ("fo", "MZXQ"),
        ("foo", "MZXW6"),
        ("foob", "MZXW6YQ"),
        ("fooba", "MZXW6YTB"),
        ("foobar", "MZXW6YTBOI"),
    ] {
        assert_eq!(base32_encode(raw.as_bytes()), enc);
        assert_eq!(base32_decode(enc).unwrap(), raw.as_bytes());
    }
    assert!(base32_decode("MZ1").is_none());
    assert!(
        base32_decode("MZ").is_none(),
        "bits de remplissage non nuls"
    );
}

#[test]
fn admin_totp_secret_is_deterministic_and_rotates_with_serial() {
    let k = [9u8; 32];
    let a = derive_admin_totp_secret(&k, 0).unwrap();
    assert_eq!(a, derive_admin_totp_secret(&k, 0).unwrap());
    assert_ne!(a, derive_admin_totp_secret(&k, 1).unwrap());
    assert_ne!(a, derive_admin_totp_secret(&[8u8; 32], 0).unwrap());
}
