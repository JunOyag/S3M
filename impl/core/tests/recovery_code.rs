//! `crypto.identity-derivation` § Code de récupération et registre KDF
//! `"admin-totp"` (`deploiement.appairage-admin`).

use s3m_core::identity_derivation::{
    base32_decode, base32_encode, recovery_code_decode, recovery_code_encode, RecoveryRole,
};
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
fn recovery_code_round_trips_the_bip39_entropy() {
    let entropy: Vec<u8> = (0..32).collect();
    let code = recovery_code_encode(RecoveryRole::Node, &entropy).unwrap();
    assert!(code.starts_with("S3M1:N:"));
    assert_eq!(code.len(), "S3M1:N:".len() + 52 + 1 + 7);
    assert!(code
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == ':'));
    let (role, back) = recovery_code_decode(&code).unwrap();
    assert_eq!((role, back), (RecoveryRole::Node, entropy.clone()));
    // Casse et espaces indifférents.
    let typed = code.to_lowercase().replace(':', " : ");
    assert_eq!(recovery_code_decode(&typed).unwrap().1, entropy);
    // 12 mots (16 octets).
    let short = recovery_code_encode(RecoveryRole::User, &entropy[..16]).unwrap();
    assert_eq!(
        recovery_code_decode(&short).unwrap(),
        (RecoveryRole::User, entropy[..16].to_vec())
    );
}

#[test]
fn recovery_code_detects_typos_and_role() {
    let entropy = [7u8; 32];
    let code = recovery_code_encode(RecoveryRole::User, &entropy).unwrap();
    let mut chars: Vec<char> = code.chars().collect();
    chars[10] = if chars[10] == 'A' { 'B' } else { 'A' };
    let typo: String = chars.into_iter().collect();
    assert!(recovery_code_decode(&typo).is_err());
    // Le rôle entre dans le contrôle : changer U en N est détecté.
    assert!(recovery_code_decode(&code.replacen(":U:", ":N:", 1)).is_err());
    assert!(recovery_code_decode("S3M2:U:AAAA:AAAAAAA").is_err());
    assert!(recovery_code_encode(RecoveryRole::User, &[0; 15]).is_err());
}

#[test]
fn admin_totp_secret_is_deterministic_and_rotates_with_serial() {
    let k = [9u8; 32];
    let a = derive_admin_totp_secret(&k, 0).unwrap();
    assert_eq!(a, derive_admin_totp_secret(&k, 0).unwrap());
    assert_ne!(a, derive_admin_totp_secret(&k, 1).unwrap());
    assert_ne!(a, derive_admin_totp_secret(&[8u8; 32], 0).unwrap());
}
