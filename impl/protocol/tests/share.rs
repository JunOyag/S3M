//! Partage (`protocols.partage`), partie commune : autorisation signée,
//! pointeur dans l'annuaire lié à la clé du propriétaire, jeton, lien et
//! invitation, codage des requêtes.

use s3m_protocol::dht::accept_record;
use s3m_protocol::exchange::*;
use s3m_protocol::share::*;

fn pk(s: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(s)
        .verifying_key()
        .to_bytes()
}

const OWNER: [u8; 32] = [0x11; 32];
const BOB: [u8; 32] = [0x22; 32];
const NOW: u64 = 1_000_000;

#[test]
fn grant_is_signed_by_its_owner() {
    let g = ShareGrant {
        owner_user_id: pk(&OWNER),
        node_id: [3; 32],
        share_id: [4; 32],
        expires_at: 0,
    };
    let (bytes, sig) = sign_grant(&OWNER, &g);
    assert_eq!(verify_grant(&bytes, &sig).unwrap(), g);
    let (_, other) = sign_grant(&BOB, &g);
    assert!(verify_grant(&bytes, &other).is_err(), "signée par un autre");
}

#[test]
fn pointer_is_readable_with_the_token_and_bound_to_the_owner_key() {
    let token = ShareToken::new(&OWNER, [7; 32]);
    let p = SharePointer {
        share_id: token.share_id(),
        is_dir: true,
        name: "Photos".into(),
        size_bytes: 0,
        modified_at: 5,
        first_block_hash: [8; 32],
        element_key: [9; 32],
        node_id: [3; 32],
        node_addrs: vec!["/ip4/1.2.3.4/tcp/4001".into()],
        owner_label: "Alice".into(),
        grant: (vec![1], vec![2]),
        revoked: false,
    };
    let env = share_entry_envelope(&OWNER, &token, &p, 1, NOW, &[1; 12]).unwrap();
    assert_eq!(open_share_entry(&env, &token, NOW).unwrap(), (1, p.clone()));
    // Les pairs n'acceptent l'entrée que sous la clé liée au propriétaire.
    let vdf = |_: &[u8; s3m_core::vdf::TAGGED_IDENTITY_LEN], _: &s3m_core::vdf::VdfProof| Ok(false);
    assert!(accept_record(&token.dht_key(), &env, None, NOW, &vdf).is_ok());
    assert!(accept_record(&[0; 32], &env, None, NOW, &vdf).is_err());
    // Un destinataire (sans la clé du propriétaire) ne peut pas réécrire.
    let forged = share_entry_envelope(
        &BOB,
        &ShareToken {
            sig_pub: token.sig_pub,
            ..ShareToken::new(&BOB, [7; 32])
        },
        &p,
        2,
        NOW,
        &[2; 12],
    )
    .unwrap();
    assert!(open_share_entry(&forged, &token, NOW).is_err());
    // Seq : une entrée plus ancienne ne remplace pas la plus récente.
    let newer = share_entry_envelope(&OWNER, &token, &p, 3, NOW, &[3; 12]).unwrap();
    assert!(accept_record(&token.dht_key(), &env, Some(&newer), NOW, &vdf).is_err());
    // Mauvais secret : illisible.
    assert!(open_share_entry(
        &env,
        &ShareToken {
            secret: [0; 32],
            ..token
        },
        NOW
    )
    .is_err());
}

#[test]
fn links_and_invites_carry_the_token() {
    let token = ShareToken::new(&OWNER, [7; 32]);
    let link = token.link();
    assert!(link.starts_with("s3m://partage#"));
    assert_eq!(ShareToken::parse(&link, &BOB, &pk(&BOB)).unwrap(), token);
    let inv = token.invite(&pk(&BOB), &[5; 32], &[6; 12]).unwrap();
    assert!(inv.starts_with("S3MS1:"));
    assert_eq!(ShareToken::parse(&inv, &BOB, &pk(&BOB)).unwrap(), token);
    assert!(
        ShareToken::parse(&inv, &OWNER, &pk(&OWNER)).is_err(),
        "pas pour lui"
    );
    assert!(ShareToken::parse("bonjour", &BOB, &pk(&BOB)).is_err());
}

#[test]
fn share_requests_roundtrip() {
    let r = Request {
        credential: Some(Credential::Share {
            grant: vec![1, 2],
            signature: vec![3],
        }),
        body: Body::GetBlock { hash: vec![4; 32] },
    };
    assert_eq!(decode_request(&encode_request(&r)).unwrap(), r);
    let r = Request {
        credential: Some(Credential::User {
            user_id: vec![1; 32],
            proof: vec![2; 32],
        }),
        body: Body::RevokeShare {
            share_id: vec![9; 32],
        },
    };
    assert_eq!(decode_request(&encode_request(&r)).unwrap(), r);
}
