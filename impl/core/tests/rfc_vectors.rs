//! Vecteurs de test externes pour les primitives de bas niveau (Phase 0,
//! id `crypto.k-attach` — conversion Ed25519->X25519 et dérivation K_attach).
//!
//! Règle absolue : tout octet attendu ci-dessous provient d'une source
//! externe publiée, citée en commentaire. Aucune valeur attendue n'est
//! produite par le code de `p2p-storage-core`. Les seuls calculs faits par
//! les tests sont des invariants structurels (symétrie Nœud/Connecteur,
//! cohérence sk<->pk, déterminisme) — jamais la génération des octets de
//! référence.
//!
//! Sources des vecteurs :
//! - RFC 7748 §5.2 — vecteurs X25519 (Alice/Bob) :
//!   https://www.rfc-editor.org/rfc/rfc7748
//! - RFC 8032 §7.1 — vecteurs Ed25519 (TEST 1, TEST 2) :
//!   https://www.rfc-editor.org/rfc/rfc8032
//! - libsodium, test/default/ed25519_convert.c + ed25519_convert.exp —
//!   conversion Ed25519->Curve25519 (sk ET pk) et points de petit ordre
//!   rejetés : https://github.com/jedisct1/libsodium
//!   Le même vecteur de conversion est asserté indépendamment par PyNaCl
//!   (tests/test_signing.py::test_key_conversion) :
//!   https://github.com/pyca/pynacl
//!
//! À vérifier aussi en WASM (`cargo test --features wasm`) avant de traiter
//! la cible Connecteur : mêmes vecteurs, autre chaîne de compilation.

use p2p_storage_core::k_attach::{
    derive_k_attach_as_node, derive_k_attach_as_user, derive_sig_priv_dispersal,
};
use p2p_storage_core::keys::{ed25519_priv_to_x25519, ed25519_pub_to_x25519};
use p2p_storage_core::CoreError;
use x25519_dalek::{x25519, PublicKey, StaticSecret, X25519_BASEPOINT_BYTES};

/// Décodage d'un vecteur hexadécimal externe (les sources citées publient
/// leurs vecteurs en hexadécimal).
fn unhex32(hex_str: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str).expect("vecteur hexadécimal valide");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

/// Dérivation graine -> clé publique Ed25519 via ed25519-dalek (interop avec
/// `crypto_sign_ed25519_seed_keypair` de libsodium — validé contre RFC 8032
/// dans `ed25519_key_derivation_matches_rfc8032_vectors`).
fn ed25519_pk_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes()
}

/// RFC 7748 §5.2 — primitive X25519, base du DH menant à K_attach.
/// Valide l'usage de `x25519-dalek` (clampage interne compris) contre les
/// vecteurs publiés de la RFC.
#[test]
fn x25519_dh_matches_rfc7748_vectors() {
    // RFC 7748 §5.2 — clé d'Alice
    let alice_sk = unhex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let alice_pk = unhex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    // RFC 7748 §5.2 — clé de Bob
    let bob_sk = unhex32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let bob_pk = unhex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    // RFC 7748 §5.2 — secret partagé
    let expected_shared = unhex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    assert_eq!(PublicKey::from(&StaticSecret::from(alice_sk)).to_bytes(), alice_pk);
    assert_eq!(PublicKey::from(&StaticSecret::from(bob_sk)).to_bytes(), bob_pk);

    let shared_a = StaticSecret::from(alice_sk).diffie_hellman(&PublicKey::from(bob_pk));
    let shared_b = StaticSecret::from(bob_sk).diffie_hellman(&PublicKey::from(alice_pk));
    assert_eq!(shared_a.as_bytes(), &expected_shared);
    assert_eq!(shared_b.as_bytes(), &expected_shared);
}

/// RFC 8032 §7.1 — TEST 1 et TEST 2 : la dérivation graine -> clé Ed25519
/// via ed25519-dalek reproduit les clés publiées. Toutes les conversions de
/// ce fichier s'appuient sur cette dérivation (interop avec
/// `crypto_sign_ed25519_seed_keypair` de libsodium).
#[test]
fn ed25519_key_derivation_matches_rfc8032_vectors() {
    // RFC 8032 §7.1 — TEST 1
    let seed_1 = unhex32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let pk_1 = unhex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    // RFC 8032 §7.1 — TEST 2
    let seed_2 = unhex32("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    let pk_2 = unhex32("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");

    assert_eq!(ed25519_pk_from_seed(&seed_1), pk_1);
    assert_eq!(ed25519_pk_from_seed(&seed_2), pk_2);
}

/// Vecteur croisé libsodium (exigé par l'en-tête de ce fichier) : conversion
/// Ed25519->X25519 contre le vecteur publié par libsodium
/// (test/default/ed25519_convert.c + .exp), corroboré par PyNaCl
/// (tests/test_signing.py::test_key_conversion). Validateur des deux
/// fonctions de `keys.rs` : sk (clamp(SHA-512(graine)[0..32])) ET pk
/// (biration u = (1+y)/(1-y)).
#[test]
fn ed25519_to_x25519_matches_libsodium_conversion_vectors() {
    // libsodium ed25519_convert.c : keypair_seed
    let seed = unhex32("421151a459faeade3d247115f94aedae42318124095afabe4d1451a559faedee");
    // libsodium ed25519_convert.exp : crypto_sign_ed25519_sk_to_curve25519
    let expected_x_sk = unhex32("8052030376d47112be7f73ed7a019293dd12ad910b654455798b4667d73de166");
    // libsodium ed25519_convert.exp : crypto_sign_ed25519_pk_to_curve25519
    let expected_x_pk = unhex32("f1814f0e8ff1043d8a44d25babff3cedcae6c22c3edaa48f857ae70de2baae50");

    // Côté clé secrète : la graine convertit exactement comme libsodium.
    let x_sk = ed25519_priv_to_x25519(&seed).expect("conversion sk valide");
    assert_eq!(x_sk, expected_x_sk);

    // Côté clé publique : la pk Ed25519 dérivée de la graine convertit
    // exactement comme libsodium.
    let ed_pk = ed25519_pk_from_seed(&seed);
    let x_pk = ed25519_pub_to_x25519(&ed_pk).expect("conversion pk valide");
    assert_eq!(x_pk, expected_x_pk);

    // Cohérence sk<->pk : la pk convertie est bien le point public du
    // scalaire converti (base X25519 u = 9 — RFC 7748 §5).
    assert_eq!(x25519(x_sk, X25519_BASEPOINT_BYTES), expected_x_pk);
}

/// Les clés publiques de petit ordre sont rejetées (CoreError::KeyConversion),
/// comme dans libsodium (ed25519_convert.c — les trois entrées dont
/// `crypto_sign_ed25519_pk_to_curve25519` renvoie -1), plus l'identité
/// (encodage 0x01...), rejetée par `ge25519_has_small_order` côté libsodium.
#[test]
fn pub_conversion_rejects_small_order_points() {
    // libsodium ed25519_convert.c — 32 premiers octets des entrées rejetées
    let zero = [0x00u8; 32];
    let mut two = [0x00u8; 32];
    two[0] = 0x02;
    let mut five = [0x00u8; 32];
    five[0] = 0x05;
    // Identité Ed25519 (y = 1) — rejetée par libsodium via has_small_order
    let mut identity = [0x00u8; 32];
    identity[0] = 0x01;

    for pk in [zero, two, five, identity] {
        assert!(matches!(
            ed25519_pub_to_x25519(&pk),
            Err(CoreError::KeyConversion)
        ));
    }
}

/// Invariant de spec (k-attach.md, section « Dérivation ») : Connecteur et
/// Nœud convergent vers le même K_attach (propriété d'échange X25519 à travers
/// nos deux conversions). Identités : RFC 8032 §7.1 TEST 1 (User) et
/// TEST 2 (Node) — vecteurs publiés ; le salt est un fixture de test (la
/// spec le laisse libre : il est fixé par le Connecteur à l'attachement réel).
#[test]
fn k_attach_is_symmetric_between_user_and_node() {
    let user_seed = unhex32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let node_seed = unhex32("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    let user_pk = ed25519_pk_from_seed(&user_seed);
    let node_pk = ed25519_pk_from_seed(&node_seed);
    let salt: &[u8] = b"k-attach-test-salt";

    let k_user =
        derive_k_attach_as_user(&user_seed, &node_pk, salt).expect("dérivation côté User");
    let k_node =
        derive_k_attach_as_node(&node_seed, &user_pk, salt).expect("dérivation côté Node");

    assert_eq!(k_user, k_node);
    assert_ne!(k_user, [0u8; 32]);
}

/// K_attach est déterministe pour un couple (identités, salt) fixés, et le
/// salt fait varier la clé (un attachement = un salt -> des K_attach
/// distincts). Fixture interne — pas de vecteur externe pour cette propriété.
#[test]
fn k_attach_derivation_is_deterministic_and_salt_dependent() {
    let user_seed = unhex32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let node_seed = unhex32("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    let node_pk = ed25519_pk_from_seed(&node_seed);
    let salt_a: &[u8] = b"salt-attachement-A";
    let salt_b: &[u8] = b"salt-attachement-B";

    let k1 = derive_k_attach_as_user(&user_seed, &node_pk, salt_a).expect("KDF");
    let k2 = derive_k_attach_as_user(&user_seed, &node_pk, salt_a).expect("KDF");
    let k3 = derive_k_attach_as_user(&user_seed, &node_pk, salt_b).expect("KDF");

    assert_eq!(k1, k2);
    assert_ne!(k1, k3);
}

/// `sig_priv_dispersal = KDF(K_attach, "dispersal-signing")` (k-attach.md,
/// section « Portée de signature dérivée ») : les deux parties calculent la
/// même clé depuis le même K_attach ; la dérivation est déterministe et
/// séparée du K_attach lui-même. Pas de vecteur externe pour cette dérivation
/// (elle est propre au protocole) — invariants internes seulement.
#[test]
fn sig_priv_dispersal_is_deterministic_and_domain_separated() {
    // Fixture K_attach arbitraire (entrée seulement, jamais valeur attendue)
    let k_attach = unhex32("f1814f0e8ff1043d8a44d25babff3cedcae6c22c3edaa48f857ae70de2baae50");
    let other_k_attach = [0x42u8; 32];

    let s1 = derive_sig_priv_dispersal(&k_attach).expect("HKDF");
    let s2 = derive_sig_priv_dispersal(&k_attach).expect("HKDF");
    let s3 = derive_sig_priv_dispersal(&other_k_attach).expect("HKDF");

    assert_eq!(s1, s2);
    assert_ne!(s1, k_attach);
    assert_ne!(s1, s3);
}