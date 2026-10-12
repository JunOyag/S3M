//! Vecteurs de test — id `crypto.symmetric-suite` (Phase 0).
//!
//! Règle absolue (même discipline que `rfc_vectors.rs`) : tout octet attendu
//! ci-dessous provient d'une source externe publiée (citée ci-dessous) ou du
//! fichier généré `vectors/symmetric_suite_expected.rs` — calculé par
//! `tests/vectors/gen_symmetric_suite_vectors.py` avec la bibliothèque
//! `cryptography`, indépendante du code testé. Aucune valeur attendue n'est
//! produite par `p2p-storage-core`.
//!
//! Sources des vecteurs :
//! - RFC 8439 §2.8.2 — vecteur AEAD_CHACHA20_POLY1305 (clé, nonce, AAD,
//!   clair → chiffré + tag) : https://www.rfc-editor.org/rfc/rfc8439
//! - RFC 5869 A.1-A.3 — vecteurs HKDF-SHA256 (A.3 : salt ∅ et info ∅) :
//!   https://www.rfc-editor.org/rfc/rfc5869
//! - RFC 4231 §4.2-4.5 (TC1-TC4) — vecteurs HMAC-SHA-256 :
//!   https://www.rfc-editor.org/rfc/rfc4231
//! - RFC 6234 §8.5 — vecteurs SHA-256 (TEST1 « abc », TEST2_1 deux blocs,
//!   TEST3 million de « a ») : https://www.rfc-editor.org/rfc/rfc6234
//! - Compositions de la page (K_nonce, K_wrap, K_block à étiquette brute,
//!   nonce synthétique, trames wrap et bloc) : fichier généré, voir l'en-tête
//!   du script Python.
//!
//! À vérifier aussi en WASM (`cargo test --features wasm`) avant de traiter
//! la cible Connecteur (même remarque que `rfc_vectors.rs`).

use p2p_storage_core::labels::P2P_STORAGE_BLOCK_V1;
use p2p_storage_core::symmetric_suite::{
    aead_open, aead_seal, canonical_encode, derive_k_nonce, derive_k_wrap, hash_sha256,
    hkdf_sha256, hmac_sha256, synthetic_nonce, AEAD_TAG_LEN, NONCE_NUL,
};
use p2p_storage_core::CoreError;

include!("vectors/symmetric_suite_expected.rs");

/// Décodage d'un vecteur hexadécimal externe.
fn unhex(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).expect("vecteur hexadécimal valide")
}

// --- Fixtures d'entrée (jamais des valeurs attendues) ---------------------
// Identiques à tests/vectors/gen_symmetric_suite_vectors.py.

fn fixture_master_key() -> Vec<u8> {
    (0..32u8).collect() // 000102…1f
}

fn fixture_k_enc() -> Vec<u8> {
    (0x20..0x40u8).collect() // 202122…3f
}

const FIXTURE_ENC_SALT: &[u8] = b"p2p-enc-salt-v1";
const FIXTURE_BLOCK_PLAINTEXT: &[u8] = b"contenu de bloc test p2p-storage";

fn fixture_wrap_plaintext() -> Vec<u8> {
    (0x40..0x60u8).collect() // 404142…5f (clé maîtresse wrappée fictive)
}

/// En-tête de version (2 o) : u16 gros-boutiste, valeur de test 0x0001 —
/// l'encodage réel de l'en-tête est porté par `deploiement.formats-serialisation`.
fn fixture_protocol_header() -> Vec<u8> {
    vec![0x00, 0x01]
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

/// RFC 4231 TC1-TC4 — HMAC-SHA-256 : clé courte, clé longue, clé + données
/// au-delà du bloc de 64 o (cas limites du HMAC).
#[test]
fn hmac_sha256_matches_rfc4231_vectors() {
    // TC1 — clé 0x0b × 20, données « Hi There »
    let mac = hmac_sha256(&[0x0bu8; 20], b"Hi There").expect("HMAC TC1");
    assert_eq!(
        mac.to_vec(),
        unhex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    );

    // TC2 — clé « Jefe », données « what do ya want for nothing? »
    let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?").expect("HMAC TC2");
    assert_eq!(
        mac.to_vec(),
        unhex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
    );

    // TC3 — clé 0xaa × 20, données 0xdd × 50
    let mac = hmac_sha256(&[0xaau8; 20], &[0xddu8; 50]).expect("HMAC TC3");
    assert_eq!(
        mac.to_vec(),
        unhex("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe")
    );

    // TC4 — clé 0x0102…19 (25 o), données 0xcd × 50
    let key = unhex("0102030405060708090a0b0c0d0e0f10111213141516171819");
    let mac = hmac_sha256(&key, &[0xcdu8; 50]).expect("HMAC TC4");
    assert_eq!(
        mac.to_vec(),
        unhex("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b")
    );
}

/// RFC 6234 §8.5 — SHA-256 : TEST1 (un bloc), TEST2_1 (deux blocs),
/// TEST3 (un million de « a »).
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
    assert_eq!(canonical_encode(&[b"abc"]), vec![0, 0, 0, 3, b'a', b'b', b'c']);
    assert_eq!(
        canonical_encode(&[b"ab", &[0u8, 1]]),
        vec![0, 0, 0, 2, b'a', b'b', 0, 0, 0, 2, 0, 1]
    );
    // Deux découpages d'une même séquence → deux entrées distinctes.
    assert_ne!(
        canonical_encode(&[b"a", b"bc"]),
        canonical_encode(&[b"ab", b"c"])
    );
    // Étiquette unique : même constat de forme, mais en pratique elle est
    // passée brute en `info` (voir K_block ci-dessous) — le préfixe u32
    // n'existe que pour les entrées multiples.
    assert_eq!(
        canonical_encode(&[b"lab"]),
        vec![0, 0, 0, 3, b'l', b'a', b'b']
    );
}

// --- Compositions (fichier généré par gen_symmetric_suite_vectors.py) ------

/// `K_nonce = HKDF-SHA256(K_enc, "p2p-storage/synthetic-nonce/v1")` sans
/// sel (§ Nonce synthétique).
#[test]
fn k_nonce_matches_generated_composition_vector() {
    let k_nonce = derive_k_nonce(&fixture_k_enc()).expect("K_nonce");
    assert_eq!(k_nonce.to_vec(), unhex(K_NONCE_HEX));
}

/// `K_wrap` — étiquette + deux versions en encodage canonique, salt ∅
/// (§ Clé de wrap). Les deux versions sont dans l'`info` : les versions
/// inversées ne partagent jamais de clé (invariant de la page).
#[test]
fn k_wrap_matches_generated_composition_vector() {
    let master = fixture_master_key();
    let k_wrap = derive_k_wrap(&master, 1, 2).expect("K_wrap");
    assert_eq!(k_wrap.to_vec(), unhex(K_WRAP_HEX));

    let other = derive_k_wrap(&master, 2, 1).expect("K_wrap, versions inversées");
    assert_ne!(other.to_vec(), unhex(K_WRAP_HEX));
}

/// `K_block` — étiquette **unique passée brute** en `info` (une seule
/// composante : pas d'encodage canonique — arbitrage de la passe code,
/// cf. note dans `symmetric_suite.rs`), salt `encryption_salt` fixé ici.
#[test]
fn k_block_single_label_info_matches_generated_composition_vector() {
    let k_block = hkdf_sha256(
        &fixture_master_key(),
        FIXTURE_ENC_SALT,
        P2P_STORAGE_BLOCK_V1.as_bytes(),
        32,
    )
    .expect("K_block");
    assert_eq!(k_block, unhex(K_BLOCK_HEX));
}

/// § Nonce synthétique — nonce = 12 premiers octets de
/// `HMAC-SHA256(K_nonce, u32(len(AAD)) ‖ AAD ‖ clair)` : valeur exacte et
/// déterminisme (même message → même nonce).
#[test]
fn synthetic_nonce_matches_generated_composition_vector() {
    let k_nonce = derive_k_nonce(&fixture_k_enc()).expect("K_nonce");
    let mut aad = fixture_protocol_header(); // en-tête de version (2 o) — valeur de test
    aad.extend_from_slice(b"block"); // contexte d'AAD (labels::AAD_CONTEXT_BLOCK)

    let nonce =
        synthetic_nonce(&k_nonce, &aad, FIXTURE_BLOCK_PLAINTEXT).expect("nonce synthétique");
    assert_eq!(nonce.to_vec(), unhex(SYNTH_NONCE_HEX));

    let replayed =
        synthetic_nonce(&k_nonce, &aad, FIXTURE_BLOCK_PLAINTEXT).expect("nonce rejoué");
    assert_eq!(nonce, replayed);
}

/// Composition wrap complète (§ Clé de wrap) : K_wrap + nonce nul + AAD
/// `en-tête ‖ "master-key-wrap" ‖ u16(vw) ‖ u16(vc)` → `wrapped_key` de
/// **48 o sans en-tête** (précision de spec : l'AAD authentifie la version,
/// l'en-tête n'est pas préfixé à la valeur stockée) ; une transplantation
/// de versions échoue au tag.
#[test]
fn wrap_composition_is_48_octets_without_header() {
    let master = fixture_master_key();
    let k_wrap = derive_k_wrap(&master, 1, 2).expect("K_wrap");

    let mut aad = fixture_protocol_header(); // en-tête de version (2 o) — valeur de test
    aad.extend_from_slice(b"master-key-wrap"); // labels::AAD_CONTEXT_MASTER_KEY_WRAP
    aad.extend_from_slice(&1u16.to_be_bytes()); // u16(version_wrappée)
    aad.extend_from_slice(&2u16.to_be_bytes()); // u16(version_courante)

    let plaintext = fixture_wrap_plaintext();
    let sealed = aead_seal(&k_wrap, &NONCE_NUL, &aad, &plaintext).expect("wrap");
    assert_eq!(sealed.len(), 32 + AEAD_TAG_LEN); // 48 o, SANS en-tête
    assert_eq!(sealed, unhex(WRAP_CT_HEX));

    let opened = aead_open(&k_wrap, &NONCE_NUL, &aad, &sealed).expect("unwrap");
    assert_eq!(opened, plaintext);

    // Transplantation : AAD portant d'autres versions sous la même clé et le
    // même nonce → tag rejeté (« échoue à la vérification du tag »).
    let mut transplanted = fixture_protocol_header();
    transplanted.extend_from_slice(b"master-key-wrap");
    transplanted.extend_from_slice(&1u16.to_be_bytes());
    transplanted.extend_from_slice(&3u16.to_be_bytes()); // version courante altérée
    assert!(matches!(
        aead_open(&k_wrap, &NONCE_NUL, &transplanted, &sealed),
        Err(CoreError::AeadFailure)
    ));
}

/// Composition bloc complète (§ Politique de nonce) : trame
/// `nonce synthétique ‖ chiffré ‖ tag` — le nonce est transmis en tête de
/// trame, l'AAD porte le contexte « block », le chiffrement est
/// déterministe.
#[test]
fn block_frame_matches_generated_composition_vector() {
    let k_nonce = derive_k_nonce(&fixture_k_enc()).expect("K_nonce");
    let mut aad = fixture_protocol_header();
    aad.extend_from_slice(b"block");
    let nonce = synthetic_nonce(&k_nonce, &aad, FIXTURE_BLOCK_PLAINTEXT).expect("nonce");

    let k_block = hkdf_sha256(
        &fixture_master_key(),
        FIXTURE_ENC_SALT,
        P2P_STORAGE_BLOCK_V1.as_bytes(),
        32,
    )
    .expect("K_block");
    let sealed = aead_seal(&k_block, &nonce, &aad, FIXTURE_BLOCK_PLAINTEXT).expect("bloc");

    let mut frame = nonce.to_vec();
    frame.extend_from_slice(&sealed);
    assert_eq!(frame, unhex(BLOCK_FRAME_HEX));
    // Le nonce synthétique est bien le préfixe transmis de la trame.
    assert_eq!(&frame[..12], unhex(SYNTH_NONCE_HEX).as_slice());

    let opened = aead_open(&k_block, &nonce, &aad, &sealed).expect("ouverture");
    assert_eq!(opened, FIXTURE_BLOCK_PLAINTEXT);
}

