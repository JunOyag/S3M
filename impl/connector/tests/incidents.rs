//! `securite.incidents-compromissions` : rotations User et Nœud.

use std::collections::HashMap;

use p2p_storage_connector::incidents::rotate_user_identity;
use p2p_storage_core::identity_derivation::{
    derive_identity_seed, derive_master_key, mnemonic_to_seed, IdentityRole,
};
use p2p_storage_core::k_block::{derive_k_block, open_block, seal_block};
use p2p_storage_core::master_key_chain::resolve_master_key;
use p2p_storage_node::incidents::{node_identity, sign_migration_pointer};
use p2p_storage_protocol::dht::{verify_migration_pointer, DhtError};
use p2p_storage_protocol::fb::dht::SignedMigrationPointer;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const OTHER: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";
const H: [u8; 2] = [0, 1];

/// Clé dérivée compromise : index suivant, nouvelle master_key ; un bloc
/// chiffré avant la rotation reste lisible via la chaîne re-wrappée, sans
/// rechiffrement. Seed compromise : nouvelle mnémonique, même garantie.
#[test]
fn user_rotation_keeps_old_blocks_readable_without_reencryption() {
    let seed = mnemonic_to_seed(MNEMONIC, "").unwrap();
    let mk1 = derive_master_key(&seed, 1).unwrap();
    let old_block = {
        let k = derive_k_block(&mk1, &[3; 16], 0).unwrap();
        seal_block(&k, &H, &[1; 12], b"ancien contenu").unwrap()
    };
    let historical: HashMap<u16, [u8; 32]> = [(1, mk1)].into();

    for (bip39, index) in [(seed, 1), (mnemonic_to_seed(OTHER, "").unwrap(), 0)] {
        let r = rotate_user_identity(&bip39, index, 2, &historical, &H).unwrap();
        assert_ne!(
            r.priv_user,
            derive_identity_seed(&seed, IdentityRole::User, 0).unwrap()
        );
        assert_ne!(r.master_key, mk1);
        let recovered = resolve_master_key(&H, &r.chain, &r.master_key, 2, 1).unwrap();
        assert_eq!(recovered, mk1);
        let k = derive_k_block(&recovered, &[3; 16], 0).unwrap();
        let clear = open_block(&k, &H, &old_block).unwrap();
        assert_eq!(&clear[..14], b"ancien contenu");
    }
}

/// Compromission de priv_node : identité suivante de la même seed, pointeur
/// signé par l'ancienne clé de secours, vérifiable sans la clé compromise.
#[test]
fn node_rotation_publishes_a_pointer_signed_by_the_old_recovery_key() {
    let seed = mnemonic_to_seed(MNEMONIC, "").unwrap();
    let old = node_identity(&seed, 0).unwrap();
    let new = node_identity(&seed, 1).unwrap();
    assert_ne!(old.node_seed, new.node_seed);
    assert_ne!(old.recovery_seed, new.recovery_seed);
    let pubk = |s: &[u8; 32]| {
        ed25519_dalek::SigningKey::from_bytes(s)
            .verifying_key()
            .to_bytes()
    };
    let (old_id, new_id, old_rec) = (
        pubk(&old.node_seed),
        pubk(&new.node_seed),
        pubk(&old.recovery_seed),
    );
    let bytes = sign_migration_pointer(&old.recovery_seed, &old_id, &new_id, 1, 100);
    let smp = flatbuffers::root::<SignedMigrationPointer>(&bytes).unwrap();
    assert_eq!(
        verify_migration_pointer(smp, &old_rec, &old_id, None).unwrap(),
        new_id
    );
    // Signé par la clé compromise elle-même : rejeté.
    let forged = sign_migration_pointer(&old.node_seed, &old_id, &new_id, 1, 100);
    let smp = flatbuffers::root::<SignedMigrationPointer>(&forged).unwrap();
    assert!(matches!(
        verify_migration_pointer(smp, &old_rec, &old_id, None),
        Err(DhtError::BadSignature)
    ));
}
