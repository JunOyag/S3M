//! Clés d'élément et clés de partage (`protocols.partage`, révision de
//! `crypto.k-block`). Valeurs attendues générées par `cryptography`.

use s3m_core::k_block::*;
use s3m_core::share::*;

include!("vectors/symmetric_suite_expected.rs");

fn arr<const N: usize>(h: &str) -> [u8; N] {
    hex::decode(h).unwrap().try_into().unwrap()
}

#[test]
fn element_key_and_derived_block_key_match_vectors() {
    let (mk, salt) = (arr(FX_MASTER_KEY_HEX), arr::<16>(FX_ENC_SALT_HEX));
    let k_elem = derive_k_elem(&mk, &salt).unwrap();
    assert_eq!(hex::encode(k_elem), K_ELEM_HEX);
    // Avec la seule clé d'élément, les mêmes clés de blocs que le propriétaire.
    assert_eq!(
        derive_k_block_from_elem(&k_elem, FX_BLOCK_INDEX).unwrap(),
        derive_k_block(&mk, &salt, FX_BLOCK_INDEX).unwrap()
    );
    assert_eq!(
        hex::encode(derive_k_block_from_elem(&k_elem, FX_BLOCK_INDEX).unwrap()),
        K_BLOCK_HEX
    );
}

#[test]
fn child_keys_are_wrapped_under_the_directory_key() {
    let (parent, child, salt) = ([1u8; 32], [2u8; 32], [3u8; 16]);
    let w = wrap_child_key(&parent, &child, &salt, &[9; 12]).unwrap();
    assert_eq!(w.len(), WRAPPED_KEY_LEN);
    assert_eq!(unwrap_child_key(&parent, &w, &salt).unwrap(), child);
    assert!(
        unwrap_child_key(&[7; 32], &w, &salt).is_err(),
        "autre répertoire"
    );
    assert!(
        unwrap_child_key(&parent, &w, &[4; 16]).is_err(),
        "autre enfant"
    );
    let mut t = w.clone();
    t[20] ^= 1;
    assert!(unwrap_child_key(&parent, &t, &salt).is_err(), "altérée");
}

#[test]
fn share_keys_match_vectors_and_invites_open_only_for_their_recipient() {
    let s = arr::<32>(FX_SECRET_HEX);
    assert_eq!(hex::encode(share_id(&s)), SHARE_ID_HEX);
    assert_eq!(
        hex::encode(share_content_key(&s).unwrap()),
        K_SHARE_CONTENT_HEX
    );
    let seed = share_signing_seed(&[5; 32], &share_id(&s)).unwrap();
    assert_ne!(
        seed,
        share_signing_seed(&[6; 32], &share_id(&s)).unwrap(),
        "propre au propriétaire"
    );
    assert_ne!(share_dht_key(&[1; 32]), share_dht_key(&[2; 32]));
    // Invitation : seul le destinataire l'ouvre.
    let alice_priv = [0x11u8; 32];
    let alice_pub = ed25519_dalek::SigningKey::from_bytes(&alice_priv)
        .verifying_key()
        .to_bytes();
    let bob_priv = [0x22u8; 32];
    let bob_pub = ed25519_dalek::SigningKey::from_bytes(&bob_priv)
        .verifying_key()
        .to_bytes();
    let inv = seal_invite(&alice_pub, &[0x33; 32], &[0x44; 12], b"jeton").unwrap();
    assert_eq!(
        open_invite(&alice_priv, &alice_pub, &inv).unwrap(),
        b"jeton"
    );
    assert!(open_invite(&bob_priv, &bob_pub, &inv).is_err());
    assert!(open_invite(&alice_priv, &alice_pub, &inv[..20]).is_err());
}
