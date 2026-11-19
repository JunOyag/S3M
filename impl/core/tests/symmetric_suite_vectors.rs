//! Vecteurs de test — id `crypto.symmetric-suite` (Phase 0, spec V3).
//!
//! Tout octet attendu provient d'une source externe publiée ou du fichier
//! généré `vectors/symmetric_suite_expected.rs` (bibliothèque `cryptography`,
//! indépendante du code testé). Aucune valeur attendue n'est produite par
//! `p2p-storage-core`.
//!
//! Sources : RFC 8439 §2.8.2 (AEAD), RFC 5869 A.1-A.3 (HKDF), RFC 6234 §8.5
//! (SHA-256) ; compositions de la convention KDF V3 : script Python.

use p2p_storage_core::labels::KDF_PREFIX;
use p2p_storage_core::symmetric_suite::{
    aead_open, aead_seal, canonical_encode, derive_k_wrap, hash_sha256, hkdf_sha256, kdf,
    AEAD_TAG_LEN, NONCE_NUL,
};
use p2p_storage_core::CoreError;

include!("vectors/symmetric_suite_expected.rs");

fn unhex(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).expect("vecteur hexadécimal valide")
}

// --- RFC 8439 §2.8.2 -------------------------------------------------------

fn rfc8439_key() -> Vec<u8> {
    unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
}

fn rfc8439_nonce() -> Vec<u8> {
    unhex("070000004041424344454647")
}

fn rfc8439_aad() -> Vec<u8> {
    unhex("50515253c0c1c2c3c4c5c6c7")
}

fn rfc8439_plaintext() -> &'static [u8] {
    b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
}

/// RFC 8439 §2.8.2 — vecteur complet AEAD_CHACHA20_POLY1305 : la trame
/// `chiffré ‖ tag` doit correspondre octet à octet, et l'ouverture doit
/// restituer le clair.
#[test]
fn aead_seal_matches_rfc8439_section_2_8_2() {
    let key = rfc8439_key();
    let nonce = rfc8439_nonce();
    let aad = rfc8439_aad();
    let plaintext = rfc8439_plaintext();
    let expected = unhex(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
         3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
         92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
         3ff4def08e4b7a9de576d26586cec64b6116\
         1ae10b594f09e26a7e902ecbd0600691",
    );

    let sealed = aead_seal(&key, &nonce, &aad, plaintext).expect("AEAD seal");
    assert_eq!(sealed, expected);
    assert_eq!(sealed.len(), plaintext.len() + AEAD_TAG_LEN);

    let opened = aead_open(&key, &nonce, &aad, &sealed).expect("AEAD open");
    assert_eq!(opened, plaintext);
}

/// Invariant § AEAD : toute falsification échoue à la vérification du tag —
/// chiffré altéré, AAD altérée, clé erronée — et les longueurs nominales
/// sont refusées par des erreurs typées (mêmes entrées que RFC 8439 §2.8.2).
#[test]
fn aead_open_rejects_forgery() {
    let key = rfc8439_key();
    let nonce = rfc8439_nonce();
    let aad = rfc8439_aad();
    let plaintext = rfc8439_plaintext();
    let sealed = aead_seal(&key, &nonce, &aad, plaintext).expect("seal");

    let mut forged_ct = sealed.clone();
    forged_ct[0] ^= 0x01;
    assert!(matches!(
        aead_open(&key, &nonce, &aad, &forged_ct),
        Err(CoreError::AeadFailure)
    ));

    let mut forged_aad = aad.clone();
    forged_aad[0] ^= 0x01;
    assert!(matches!(
        aead_open(&key, &nonce, &forged_aad, &sealed),
        Err(CoreError::AeadFailure)
    ));

    let mut wrong_key = key.clone();
    wrong_key[0] ^= 0x01;
    assert!(matches!(
        aead_open(&wrong_key, &nonce, &aad, &sealed),
        Err(CoreError::AeadFailure)
    ));

    assert!(matches!(
        aead_seal(&key[..16], &nonce, &aad, plaintext),
        Err(CoreError::InvalidKeyLength {
            expected: 32,
            got: 16
        })
    ));
    assert!(matches!(
        aead_seal(&key, &nonce[..8], &aad, plaintext),
        Err(CoreError::InvalidNonceLength {
            expected: 12,
            got: 8
        })
    ));
}

/// RFC 5869 A.1-A.3 — HKDF-SHA256 : sorties OKM exactes, dont le cas
/// « salt ∅, info ∅ » (A.3) qui valide le `salt` vide de la spec.
#[test]
fn hkdf_sha256_matches_rfc5869_vectors() {
    // A.1 — test de base, L = 42
    let ikm = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = unhex("000102030405060708090a0b0c");
    let info = unhex("f0f1f2f3f4f5f6f7f8f9");
    let okm = hkdf_sha256(&ikm, &salt, &info, 42).expect("HKDF A.1");
    assert_eq!(
        okm,
        unhex(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865"
        )
    );

    // A.2 — entrées/sorties longues (80 o), L = 82
    let ikm = unhex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
         202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
         404142434445464748494a4b4c4d4e4f",
    );
    let salt = unhex(
        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
         808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
         a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
    );
    let info = unhex(
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
         d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef\
         f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
    );
    let okm = hkdf_sha256(&ikm, &salt, &info, 82).expect("HKDF A.2");
    assert_eq!(
        okm,
        unhex(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
             59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
             cc30c58179ec3e87c14c01d5c1f3434f1d87"
        )
    );

    // A.3 — salt ∅ et info ∅ (cas « sans sel » de la spec)
    let ikm = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let okm = hkdf_sha256(&ikm, &[], &[], 42).expect("HKDF A.3");
    assert_eq!(
        okm,
        unhex(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8"
        )
    );
}

#[test]
fn sha256_matches_rfc6234_vectors() {
    assert_eq!(
        hash_sha256(b"abc").to_vec(),
        unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
    assert_eq!(
        hash_sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").to_vec(),
        unhex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
    );
    let million_a = vec![b'a'; 1_000_000];
    assert_eq!(
        hash_sha256(&million_a).to_vec(),
        unhex("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
    );
}

/// § KDF — encodage canonique : chaque composante préfixée de sa longueur
/// u32 gros-boutiste ; la frontière entre composantes ne peut pas être
/// ambiguë. Invariant structurel de la page (pas un vecteur externe).
#[test]
fn canonical_encode_matches_spec_layout() {
    assert_eq!(
        canonical_encode(&[b"abc"]),
        vec![0, 0, 0, 3, b'a', b'b', b'c']
    );
    assert_eq!(
        canonical_encode(&[b"ab", &[0u8, 1]]),
        vec![0, 0, 0, 2, b'a', b'b', 0, 0, 0, 2, 0, 1]
    );
    // Deux découpages d'une même séquence → deux entrées distinctes.
    assert_ne!(
        canonical_encode(&[b"a", b"bc"]),
        canonical_encode(&[b"ab", b"c"])
    );
}

// --- Convention KDF V3 (fichier généré) ------------------------------------

/// § KDF — `info = "p2p-storage/kdf/v1" ‖ L(label) ‖ L(entrées…)`, IKM =
/// secret seul, sel séparé : valeur exacte contre `cryptography`.
#[test]
fn kdf_convention_matches_generated_vector() {
    let k = kdf(&unhex(FX_SECRET_HEX), "test-label", b"salt", &[b"a", b"bc"]).expect("kdf");
    assert_eq!(k.to_vec(), unhex(KDF_GENERIC_HEX));
    assert_eq!(KDF_PREFIX, "p2p-storage/kdf/v1");
}

/// § KDF — `L(·)` rend les frontières non ambiguës : `("a","bc")` et
/// `("ab","c")` donnent deux clés distinctes.
#[test]
fn kdf_public_input_boundaries_are_unambiguous() {
    let secret = unhex(FX_SECRET_HEX);
    let swapped = kdf(&secret, "test-label", b"salt", &[b"ab", b"c"]).expect("kdf");
    assert_eq!(swapped.to_vec(), unhex(KDF_GENERIC_SWAPPED_HEX));
    assert_ne!(swapped.to_vec(), unhex(KDF_GENERIC_HEX));
}

/// § KDF — les entrées publiques ne vont jamais dans l'IKM : mettre le
/// secret seul ou concaténé à l'entrée change la clé.
#[test]
fn kdf_secret_is_the_only_ikm() {
    let secret = unhex(FX_SECRET_HEX);
    let mut mixed = secret.clone();
    mixed.extend_from_slice(b"a");
    let a = kdf(&secret, "test-label", b"", &[b"a"]).expect("kdf");
    let b = kdf(&mixed, "test-label", b"", &[]).expect("kdf");
    assert_ne!(a, b);
}

/// § Clé de wrap — `K_wrap = KDF(master_key[vc], "master-key-wrap", —,
/// u16(vw), u16(vc))` ; versions inversées → autre clé.
#[test]
fn k_wrap_matches_generated_vector() {
    let master = unhex(FX_MASTER_KEY_HEX);
    let k_wrap = derive_k_wrap(&master, 1, 2).expect("K_wrap");
    assert_eq!(k_wrap.to_vec(), unhex(K_WRAP_HEX));
    assert_ne!(
        derive_k_wrap(&master, 2, 1).expect("K_wrap").to_vec(),
        unhex(K_WRAP_HEX)
    );
}

/// § Clé de wrap — nonce nul, `wrapped_key` de 48 o sans en-tête ;
/// transplantation de versions → tag rejeté.
#[test]
fn wrap_composition_is_48_octets_without_header() {
    let k_wrap = derive_k_wrap(&unhex(FX_MASTER_KEY_HEX), 1, 2).expect("K_wrap");
    let header = unhex(FX_PROTO_HEADER_HEX);
    let aad = [
        &header[..],
        b"master-key-wrap",
        &1u16.to_be_bytes(),
        &2u16.to_be_bytes(),
    ]
    .concat();
    let plaintext = unhex(FX_WRAP_PLAINTEXT_HEX);
    let sealed = aead_seal(&k_wrap, &NONCE_NUL, &aad, &plaintext).expect("wrap");
    assert_eq!(sealed.len(), 32 + AEAD_TAG_LEN);
    assert_eq!(sealed, unhex(WRAP_CT_HEX));
    assert_eq!(
        aead_open(&k_wrap, &NONCE_NUL, &aad, &sealed).expect("unwrap"),
        plaintext
    );
    let transplanted = [
        &header[..],
        b"master-key-wrap",
        &1u16.to_be_bytes(),
        &3u16.to_be_bytes(),
    ]
    .concat();
    assert!(matches!(
        aead_open(&k_wrap, &NONCE_NUL, &transplanted, &sealed),
        Err(CoreError::AeadFailure)
    ));
}
