//! Partage (`protocols.partage#lecture`), côté Nœud : blocs servis sur
//! autorisation signée du propriétaire, refus hors conditions, retrait,
//! débit limité.

use s3m_core::k_attach::derive_k_attach_as_user;
use s3m_node::exchange::*;
use s3m_protocol::exchange::*;
use s3m_protocol::share::{sign_grant, ShareGrant, BLOCKS_PER_MINUTE};

const NODE: [u8; 32] = [0x10; 32];
const OWNER: [u8; 32] = [0x40; 32];
const STRANGER: [u8; 32] = [0x50; 32];
const SALT: [u8; 16] = [7; 16];
const NOW: u64 = 1_000_000;

fn pk(s: &[u8; 32]) -> Id {
    ed25519_dalek::SigningKey::from_bytes(s)
        .verifying_key()
        .to_bytes()
}

fn owner_req(body: Body) -> Request {
    let k = derive_k_attach_as_user(&OWNER, &pk(&NODE), &SALT).unwrap();
    Request {
        credential: Some(Credential::User {
            user_id: pk(&OWNER).to_vec(),
            proof: connector_proof(&k, b"c", b"n").to_vec(),
        }),
        body,
    }
}

fn share_req(signer: &[u8; 32], g: &ShareGrant, hash: &[u8]) -> Request {
    let (grant, signature) = sign_grant(signer, g);
    Request {
        credential: Some(Credential::Share { grant, signature }),
        body: Body::GetBlock {
            hash: hash.to_vec(),
        },
    }
}

#[test]
fn share_grant_reads_only_the_owner_blocks_until_revoked() {
    let mut s = NodeService::new(NODE);
    s.users.insert(
        pk(&OWNER),
        UserAccount {
            salt: SALT.to_vec(),
            quota_bytes: 1 << 30,
            used_bytes: 0,
            root: [0; 32],
        },
    );
    let block = vec![0xAB; 65_536];
    let stored = s.handle(
        b"c",
        None,
        b"n",
        owner_req(Body::PutBlock {
            data: block.clone(),
        }),
        NOW,
    );
    let Response::Stored(hash) = stored else {
        panic!("{stored:?}")
    };
    let g = ShareGrant {
        owner_user_id: pk(&OWNER),
        node_id: pk(&NODE),
        share_id: [1; 32],
        expires_at: 0,
    };
    let read = |s: &mut NodeService, signer: &[u8; 32], g: &ShareGrant, now| {
        s.handle(b"x", None, b"n", share_req(signer, g, &hash), now)
    };
    assert_eq!(
        read(&mut s, &OWNER, &g, NOW),
        Response::BlockData(block.clone())
    );
    // Signée par un autre, pour un autre Nœud, expirée, propriétaire inconnu : refus.
    assert_eq!(
        read(&mut s, &STRANGER, &g, NOW),
        Response::Failure(Refusal::Unauthorized)
    );
    let other_node = ShareGrant {
        node_id: [9; 32],
        ..g.clone()
    };
    assert_eq!(
        read(&mut s, &OWNER, &other_node, NOW),
        Response::Failure(Refusal::Unauthorized)
    );
    let expired = ShareGrant {
        expires_at: NOW,
        ..g.clone()
    };
    assert_eq!(
        read(&mut s, &OWNER, &expired, NOW),
        Response::Failure(Refusal::Unauthorized)
    );
    let unknown = ShareGrant {
        owner_user_id: pk(&STRANGER),
        ..g.clone()
    };
    assert_eq!(
        read(&mut s, &STRANGER, &unknown, NOW),
        Response::Failure(Refusal::Unauthorized)
    );
    // Retrait par le propriétaire.
    assert_eq!(
        s.handle(
            b"c",
            None,
            b"n",
            owner_req(Body::RevokeShare {
                share_id: vec![1; 32]
            }),
            NOW
        ),
        Response::Ack { freed: 0 }
    );
    assert_eq!(
        read(&mut s, &OWNER, &g, NOW),
        Response::Failure(Refusal::Unauthorized)
    );
    // Débit limité par partage et par minute.
    let g2 = ShareGrant {
        share_id: [2; 32],
        ..g
    };
    for _ in 1..BLOCKS_PER_MINUTE {
        read(&mut s, &OWNER, &g2, NOW);
    }
    assert_eq!(
        read(&mut s, &OWNER, &g2, NOW),
        Response::BlockData(block.clone())
    );
    assert_eq!(
        read(&mut s, &OWNER, &g2, NOW),
        Response::Failure(Refusal::RateLimited)
    );
    assert_eq!(
        read(&mut s, &OWNER, &g2, NOW + 60),
        Response::BlockData(block)
    );
}
