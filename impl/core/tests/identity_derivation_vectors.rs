//! Vecteurs et invariants pour `crypto.identity-derivation` (Phase 0).
//!
//! Vecteurs externes officiels :
//! - BIP-39 : Trezor test vectors (trezor/python-mnemonic, `vectors.json`) —
//!   seed PBKDF2-HMAC-SHA512, 2048 itérations, sel `"mnemonic"+passphrase`.
//! - SLIP-0010 : test vectors ed25519 du spec (satoshilabs/slips) —
//!   `HMAC-SHA512(clé="ed25519 seed")` + dérivations durcies.
//!
//! Invariants structurels exigés par la page (`docs/03-crypto/
//! identity-derivation.md`) :
//! - déterminisme de la chaîne complète (phrase -> seed -> identité) ;
//! - séparation des rôles (User/Node/NodeRecovery/MasterKey) ;
//! - sensibilité à l'index (rotation -> nouvelle identité, jamais réutilisée) ;
//! - sensibilité à la passphrase (mauvaise passphrase = autre identité,
//!   **aucune erreur** — page spec, § Passphrase) ;
//! - borne `uint16` de `master_key[version]` ;
//! - clé de secours en miroir (rôle `2'` index `i` accompagne rôle `1'`
//!   index `i`, sans réutiliser la même clé).
//!
//! Règle de fixtures : phrases mnémoniques et seeds des vecteurs publiés —
//! jamais comme valeurs attendues d'une dérivation propre au protocole.

use p2p_storage_core::identity_derivation::{
    derive_identity_seed, derive_master_key, mnemonic_to_seed, slip10_hardened_child,
    slip10_master_key, IdentityRole, HARDENED, PURPOSE,
};

/// BIP-39 / Trezor vectors : seed attendue, passphrase "TREZOR".
const TREVOR_ABANDON_ABOUT_TREZOR: [u8; 64] = [
    0xc5, 0x52, 0x57, 0xc3, 0x60, 0xc0, 0x7c, 0x72, 0x02, 0x9a, 0xeb, 0xc1, 0xb5, 0x3c, 0x05, 0xed,
    0x03, 0x62, 0xad, 0xa3, 0x8e, 0xad, 0x3e, 0x3e, 0x9e, 0xfa, 0x37, 0x08, 0xe5, 0x34, 0x95, 0x53,
    0x1f, 0x09, 0xa6, 0x98, 0x75, 0x99, 0xd1, 0x82, 0x64, 0xc1, 0xe1, 0xc9, 0x2f, 0x2c, 0xf1, 0x41,
    0x63, 0x0c, 0x7a, 0x3c, 0x4a, 0xb7, 0xc8, 0x1b, 0x2f, 0x00, 0x16, 0x98, 0xe7, 0x46, 0x3b, 0x04,
];
/// BIP-39 / Trezor vectors : même phrase, passphrase **vide** (défaut du
/// protocole).
const TREVOR_ABANDON_ABOUT_EMPTY: [u8; 64] = [
    0x5e, 0xb0, 0x0b, 0xbd, 0xdc, 0xf0, 0x69, 0x08, 0x48, 0x89, 0xa8, 0xab, 0x91, 0x55, 0x56, 0x81,
    0x65, 0xf5, 0xc4, 0x53, 0xcc, 0xb8, 0x5e, 0x70, 0x81, 0x1a, 0xae, 0xd6, 0xf6, 0xda, 0x5f, 0xc1,
    0x9a, 0x5a, 0xc4, 0x0b, 0x38, 0x9c, 0xd3, 0x70, 0xd0, 0x86, 0x20, 0x6d, 0xec, 0x8a, 0xa6, 0xc4,
    0x3d, 0xae, 0xa6, 0x69, 0x0f, 0x20, 0xad, 0x3d, 0x8d, 0x48, 0xb2, 0xd2, 0xce, 0x9e, 0x38, 0xe4,
];
/// BIP-39 / Trezor vectors : deuxième phrase, passphrase "TREZOR".
const TREVOR_LEGAL_WINNER_TREZOR: [u8; 64] = [
    0x2e, 0x89, 0x05, 0x81, 0x9b, 0x87, 0x23, 0xfe, 0x2c, 0x1d, 0x16, 0x18, 0x60, 0xe5, 0xee, 0x18,
    0x30, 0x31, 0x8d, 0xbf, 0x49, 0xa8, 0x3b, 0xd4, 0x51, 0xcf, 0xb8, 0x44, 0x0c, 0x28, 0xbd, 0x6f,
    0xa4, 0x57, 0xfe, 0x12, 0x96, 0x10, 0x65, 0x59, 0xa3, 0xc8, 0x09, 0x37, 0xa1, 0xc1, 0x06, 0x9b,
    0xe3, 0xa3, 0xa5, 0xbd, 0x38, 0x1e, 0xe6, 0x26, 0x0e, 0x8d, 0x97, 0x39, 0xfc, 0xe1, 0xf6, 0x07,
];

/// Phrase du vecteur BIP-39 « abandon … about » (checksum valide — vecteur
/// publié ; la validation du checksum reste côté applicatif, le noyau ne
/// convertit que la chaîne).
const MNEMONIC_ABANDON_ABOUT: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// Phrase du vecteur BIP-39 « legal winner … yellow ».
const MNEMONIC_LEGAL_WINNER: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";

/// SLIP-0010, « Test vector 2 for ed25519 » — seed 64 o (la spec autorise
/// 16 à 64 o ; ce vecteur cadre avec la seed BIP-39 de 64 o du protocole),
/// clé maître `m`.
const SLIP10_SEED: [u8; 64] = [
    0xff, 0xfc, 0xf9, 0xf6, 0xf3, 0xf0, 0xed, 0xea, 0xe7, 0xe4, 0xe1, 0xde, 0xdb, 0xd8, 0xd5, 0xd2,
    0xcf, 0xcc, 0xc9, 0xc6, 0xc3, 0xc0, 0xbd, 0xba, 0xb7, 0xb4, 0xb1, 0xae, 0xab, 0xa8, 0xa5, 0xa2,
    0x9f, 0x9c, 0x99, 0x96, 0x93, 0x90, 0x8d, 0x8a, 0x87, 0x84, 0x81, 0x7e, 0x7b, 0x78, 0x75, 0x72,
    0x6f, 0x6c, 0x69, 0x66, 0x63, 0x60, 0x5d, 0x5a, 0x57, 0x54, 0x51, 0x4e, 0x4b, 0x48, 0x45, 0x42,
];
const SLIP10_MASTER_KEY: [u8; 32] = [
    0x17, 0x1c, 0xb8, 0x8b, 0x1b, 0x3c, 0x1d, 0xb2, 0x5a, 0xdd, 0x59, 0x97, 0x12, 0xe3, 0x62, 0x45,
    0xd7, 0x5b, 0xc6, 0x5a, 0x1a, 0x5c, 0x9e, 0x18, 0xd7, 0x6f, 0x9f, 0x2b, 0x1e, 0xab, 0x40, 0x12,
];
const SLIP10_MASTER_CHAIN_CODE: [u8; 32] = [
    0xef, 0x70, 0xa7, 0x4d, 0xb9, 0xc3, 0xa5, 0xaf, 0x93, 0x1b, 0x5f, 0xe7, 0x3e, 0xd8, 0xe1, 0xa5,
    0x34, 0x64, 0x13, 0x36, 0x54, 0xfd, 0x55, 0xe7, 0xa6, 0x6f, 0x85, 0x70, 0xb8, 0xe3, 0x3c, 0x3b,
];
/// SLIP-0010, « Test vector 2 for ed25519 » — enfant durci `m/0'`.
const SLIP10_CHILD_0H_KEY: [u8; 32] = [
    0x15, 0x59, 0xeb, 0x2b, 0xbe, 0xc5, 0x79, 0x0b, 0x0c, 0x65, 0xd8, 0x69, 0x3e, 0x4d, 0x08, 0x75,
    0xb1, 0x74, 0x7f, 0x49, 0x70, 0xae, 0x8b, 0x65, 0x04, 0x86, 0xed, 0x74, 0x70, 0x84, 0x56, 0x35,
];
const SLIP10_CHILD_0H_CHAIN_CODE: [u8; 32] = [
    0x0b, 0x78, 0xa3, 0x22, 0x6f, 0x91, 0x5c, 0x08, 0x2b, 0xf1, 0x18, 0xf8, 0x36, 0x18, 0xa6, 0x18,
    0xab, 0x6d, 0xec, 0x79, 0x37, 0x52, 0x62, 0x4c, 0xbe, 0xb6, 0x22, 0xac, 0xb5, 0x62, 0x86, 0x2d,
];
/// Vecteur Trezor : phrase « abandon … about » + passphrase « TREZOR » ->
/// seed BIP-39 publiée. Fige le sel `"mnemonic"+passphrase` et le nombre
/// d'itérations (2048).
#[test]
fn bip39_seed_matches_trezor_vector_trezor_passphrase() {
    let seed = mnemonic_to_seed(MNEMONIC_ABANDON_ABOUT, "TREZOR").expect("PBKDF2");
    assert_eq!(seed, TREVOR_ABANDON_ABOUT_TREZOR);
}

/// Vecteur Trezor : même phrase, passphrase **vide** (défaut du protocole) ->
/// seed distincte publiée — la passphrase est bien un paramètre de la KDF.
#[test]
fn bip39_seed_matches_trezor_vector_empty_passphrase() {
    let seed = mnemonic_to_seed(MNEMONIC_ABANDON_ABOUT, "").expect("PBKDF2");
    assert_eq!(seed, TREVOR_ABANDON_ABOUT_EMPTY);
}

/// Vecteur Trezor : deuxième phrase indépendante (« legal winner … yellow »,
/// passphrase « TREZOR ») — la chaîne n'est pas figée sur une phrase unique.
#[test]
fn bip39_seed_matches_trezor_vector_second_mnemonic() {
    let seed = mnemonic_to_seed(MNEMONIC_LEGAL_WINNER, "TREZOR").expect("PBKDF2");
    assert_eq!(seed, TREVOR_LEGAL_WINNER_TREZOR);
}

/// Vecteur SLIP-0010 (ed25519) : seed publiée -> clé maître `(k, c)`
/// publiée. Fige `HMAC-SHA512(clé = "ed25519 seed")` et le split IL/IR.
#[test]
fn slip10_master_key_matches_spec_vector() {
    let (k, c) = slip10_master_key(&SLIP10_SEED).expect("HMAC-SHA512");
    assert_eq!(k, SLIP10_MASTER_KEY);
    assert_eq!(c, SLIP10_MASTER_CHAIN_CODE);
}

/// Vecteur SLIP-0010 (ed25519) : enfant durci `m/0'` publié. Fige la
/// construction `0x00 ‖ k_parent ‖ ser32(index + 0x80000000)`.
#[test]
fn slip10_hardened_child_matches_spec_vector() {
    let (k, c) =
        slip10_hardened_child(&SLIP10_MASTER_KEY, &SLIP10_MASTER_CHAIN_CODE, 0).expect("HMAC");
    assert_eq!(k, SLIP10_CHILD_0H_KEY);
    assert_eq!(c, SLIP10_CHILD_0H_CHAIN_CODE);
}

/// Page spec, § « Chaîne de dérivation » : purpose durci = 0x80703270 (« p2p »
/// en ASCII, écriture hexadécimale de l'indice fixé par la page).
#[test]
fn purpose_hardened_serialization_is_0x80703270() {
    assert_eq!(PURPOSE, 0x0070_3270);
    assert_eq!(PURPOSE + HARDENED, 0x8070_3270);
}

/// Mêmes entrées -> même identité (page spec, § « Découverte de l'index » :
/// la restauration à froid repose sur la re-dérivation déterministe depuis la
/// seed seule). Sortie non nulle — graine Ed25519 RFC 8032 de 32 o.
#[test]
fn identity_derivation_is_deterministic() {
    let seed = mnemonic_to_seed(MNEMONIC_ABANDON_ABOUT, "").expect("PBKDF2");
    let id1 = derive_identity_seed(&seed, IdentityRole::User, 0).expect("dérivation");
    let id2 = derive_identity_seed(&seed, IdentityRole::User, 0).expect("dérivation");
    assert_eq!(id1, id2);
    assert_ne!(id1, [0u8; 32]);
}

/// Rôles distincts à index égal -> quatre clés distinctes (page spec, §
/// « Rôles » : chaque branche du chemin désigne un usage exclusif ; le rôle
/// `3'` « ne signe jamais et ne sert à aucun échange DH »).
#[test]
fn roles_are_domain_separated() {
    let seed = mnemonic_to_seed(MNEMONIC_ABANDON_ABOUT, "").expect("PBKDF2");
    let user = derive_identity_seed(&seed, IdentityRole::User, 0).expect("dérivation");
    let node = derive_identity_seed(&seed, IdentityRole::Node, 0).expect("dérivation");
    let recovery = derive_identity_seed(&seed, IdentityRole::NodeRecovery, 0).expect("dérivation");
    let master = derive_identity_seed(&seed, IdentityRole::MasterKey, 0).expect("dérivation");
    assert_ne!(user, node);
    assert_ne!(user, recovery);
    assert_ne!(user, master);
    assert_ne!(node, recovery);
    assert_ne!(node, master);
    assert_ne!(recovery, master);
}

/// Page spec, § « Règle d'index » : rotation d'identité = index suivant, un
/// index fuité n'est jamais réutilisé — l'index doit changer la clé.
#[test]
fn identity_index_rotation_changes_the_key() {
    let seed = mnemonic_to_seed(MNEMONIC_ABANDON_ABOUT, "").expect("PBKDF2");
    let idx0 = derive_identity_seed(&seed, IdentityRole::User, 0).expect("dérivation");
    let idx1 = derive_identity_seed(&seed, IdentityRole::User, 1).expect("dérivation");
    assert_ne!(idx0, idx1);
}

/// Page spec, § « Clé de secours en miroir » : la clé de secours d'un Node
/// d'index `i` occupe l'index `i` du rôle `2'` — elle accompagne ce Node
/// (même index) sans jamais être sa clé de signature, et la compromission
/// d'une clé de secours n'invalide pas les autres (chaque index a la sienne).
#[test]
fn node_recovery_key_accompanies_node_index_without_reuse() {
    let seed = mnemonic_to_seed(MNEMONIC_ABANDON_ABOUT, "").expect("PBKDF2");
    let node_i = derive_identity_seed(&seed, IdentityRole::Node, 7).expect("dérivation");
    let recovery_i = derive_identity_seed(&seed, IdentityRole::NodeRecovery, 7).expect("dérivation");
    let recovery_j = derive_identity_seed(&seed, IdentityRole::NodeRecovery, 8).expect("dérivation");
    // Miroir : même index, mais clé distincte de la clé Node accompagnée.
    assert_ne!(recovery_i, node_i);
    // Isolation : chaque Node d'index distinct a sa propre clé de secours.
    assert_ne!(recovery_i, recovery_j);
}

/// Page spec, § « Rôles » + § « Règle d'index » : `master_key[version]` est
/// un compteur `uint16` **indépendant** de l'index d'identité — deux
/// versions donnent deux clés maîtresses distinctes, et le raccourci typé
/// équivaut au chemin rôle `3'` générique.
#[test]
fn master_key_versions_are_independent_and_bounded() {
    let seed = mnemonic_to_seed(MNEMONIC_ABANDON_ABOUT, "").expect("PBKDF2");
    let v0 = derive_master_key(&seed, 0).expect("dérivation");
    let v1 = derive_master_key(&seed, 1).expect("dérivation");
    let v_max = derive_master_key(&seed, u16::MAX).expect("dérivation");
    assert_ne!(v0, v1);
    assert_ne!(v0, v_max);
    assert_ne!(v1, v_max);
    // Le raccourci typé = chemin générique m/0x703270'/3'/version'.
    let via_role = derive_identity_seed(&seed, IdentityRole::MasterKey, u32::from(u16::MAX))
        .expect("dérivation");
    assert_eq!(v_max, via_role);
}

/// Page spec, § « Passphrase » : une passphrase erronée **ne produit aucune
/// erreur** — elle dérive une identité valide mais différente (le bootstrap
/// à froid conclut « aucune entrée trouvée », pas « dérivation échouée »).
#[test]
fn wrong_passphrase_yields_a_different_identity_without_error() {
    let good = mnemonic_to_seed(MNEMONIC_ABANDON_ABOUT, "").expect("PBKDF2");
    let wrong = mnemonic_to_seed(MNEMONIC_ABANDON_ABOUT, "mot-de-passe-errone").expect("PBKDF2");
    assert_ne!(good, wrong);
    let id_good = derive_identity_seed(&good, IdentityRole::User, 0).expect("dérivation");
    let id_wrong = derive_identity_seed(&wrong, IdentityRole::User, 0).expect("dérivation");
    assert_ne!(id_good, id_wrong);
}

/// SLIP-0010 n'autorise que des index durcis < 2^31 pour ed25519 — un index
/// hors bornes est rejeté (jamais masqué silencieusement).
#[test]
fn out_of_range_hardened_index_is_rejected() {
    let seed = mnemonic_to_seed(MNEMONIC_ABANDON_ABOUT, "").expect("PBKDF2");
    let (k, c) = slip10_master_key(&seed).expect("HMAC-SHA512");
    assert!(slip10_hardened_child(&k, &c, HARDENED).is_err());
    assert!(slip10_hardened_child(&k, &c, u32::MAX).is_err());
}