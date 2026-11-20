//! `protocols.echange-blocs` (partie node) : service et transport.

use std::sync::{Arc, Mutex};

use s3m_core::k_attach::derive_k_attach_as_user;
use s3m_core::symmetric_suite::hash_sha256;
use s3m_node::exchange::*;
use s3m_node::pos::challenge_response;
use s3m_node::tombstones::TombstoneNotice;
use s3m_protocol::exchange::*;

const NODE: [u8; 32] = [0x10; 32];
const PARTNER: [u8; 32] = [0x20; 32];
const NEW_NODE: [u8; 32] = [0x30; 32];
const USER: [u8; 32] = [0x40; 32];
const DEVICE: [u8; 32] = [0x50; 32];
const SALT: [u8; 16] = [7; 16];
const NOW: u64 = 1_000_000;

fn pk(s: &[u8; 32]) -> Id {
    ed25519_dalek::SigningKey::from_bytes(s)
        .verifying_key()
        .to_bytes()
}

fn account(quota_bytes: u64) -> UserAccount {
    UserAccount {
        salt: SALT.to_vec(),
        quota_bytes,
        used_bytes: 0,
        root: [0; 32],
    }
}

fn service_with_user(seed: [u8; 32], quota: u64) -> NodeService {
    let mut s = NodeService::new(seed);
    s.users.insert(pk(&USER), account(quota));
    s
}

/// Requête du Connecteur vers le Nœud `node`, sur la connexion `from` → `local`.
fn user_req(node: &[u8; 32], body: Body, from: &[u8], local: &[u8]) -> Request {
    let k = derive_k_attach_as_user(&USER, &pk(node), &SALT).unwrap();
    Request {
        credential: Some(Credential::User {
            user_id: pk(&USER).to_vec(),
            proof: connector_proof(&k, from, local).to_vec(),
        }),
        body,
    }
}

fn plain(body: Body) -> Request {
    Request {
        credential: None,
        body,
    }
}

fn rescue(grant: &SignedGrant, from: &[u8], hash: &Id) -> Request {
    Request {
        credential: Some(Credential::Rescue {
            grant: grant.clone(),
            proof: rescue_session_proof(&DEVICE, from, b"p"),
        }),
        body: Body::FetchFragment {
            hash: hash.to_vec(),
        },
    }
}

#[test]
fn attached_connector_reads_writes_and_commits_with_conflict_detection() {
    let mut s = service_with_user(NODE, 100);
    let call = |s: &mut NodeService, body: Body| {
        s.handle(b"c", None, b"n", user_req(&NODE, body, b"c", b"n"), NOW)
    };
    let h = hash_sha256(&[1; 60]);
    assert_eq!(
        call(&mut s, Body::PutBlock { data: vec![1; 60] }),
        Response::Stored(h.to_vec())
    );
    assert_eq!(
        call(&mut s, Body::GetBlock { hash: h.to_vec() }),
        Response::BlockData(vec![1; 60])
    );
    assert_eq!(
        call(&mut s, Body::PutBlock { data: vec![2; 60] }),
        Response::Failure(Refusal::QuotaExceeded)
    );
    let commit = |base: u8, new: u8| Body::CommitRoot {
        base_root: vec![base; 32],
        new_root: vec![new; 32],
    };
    assert_eq!(
        call(&mut s, commit(0, 5)),
        Response::RootState {
            committed: true,
            current_root: vec![5; 32]
        }
    );
    assert_eq!(
        call(&mut s, commit(0, 6)),
        Response::RootState {
            committed: false,
            current_root: vec![5; 32]
        }
    );
    // Preuve reprise sur une autre connexion, ou absence d'identifiant.
    let stolen = user_req(&NODE, Body::GetBlock { hash: h.to_vec() }, b"c", b"n");
    assert_eq!(
        s.handle(b"thief", None, b"n", stolen, NOW),
        Response::Failure(Refusal::Unauthorized)
    );
    assert_eq!(
        s.handle(
            b"c",
            None,
            b"n",
            plain(Body::GetBlock { hash: h.to_vec() }),
            NOW
        ),
        Response::Failure(Refusal::Unauthorized)
    );
}

#[test]
fn partner_gets_signed_receipt_challenge_and_tombstone_within_barter_balance() {
    let mut p = NodeService::new(PARTNER);
    p.partners.insert(
        pk(&NODE),
        PartnerState {
            allowance: 1,
            ..Default::default()
        },
    );
    let me = Some(pk(&NODE));
    let h = hash_sha256(&[9; 40]);
    let r = p.handle(
        b"n",
        me,
        b"p",
        plain(Body::StoreFragment { data: vec![9; 40] }),
        NOW,
    );
    let Response::FragmentReceipt { hash, signature } = r else {
        panic!("{r:?}")
    };
    assert_eq!(hash, h.to_vec());
    assert!(verify_receipt(&pk(&PARTNER), &h, &pk(&NODE), &signature));
    assert_eq!(
        p.handle(
            b"n",
            me,
            b"p",
            plain(Body::StoreFragment { data: vec![8; 40] }),
            NOW
        ),
        Response::Failure(Refusal::QuotaExceeded),
        "solde de troc épuisé"
    );
    let challenge = plain(Body::Challenge {
        hash: h.to_vec(),
        nonce: vec![3; 32],
    });
    assert_eq!(
        p.handle(b"n", me, b"p", challenge, NOW),
        Response::ChallengeResponse(challenge_response(&[9; 40], &[3; 32]).to_vec())
    );
    let stranger = plain(Body::FetchFragment { hash: h.to_vec() });
    assert_eq!(
        p.handle(b"x", Some(pk(&NEW_NODE)), b"p", stranger, NOW),
        Response::Failure(Refusal::Unauthorized),
        "Nœud inconnu"
    );
    let t = TombstoneNotice::sign(&NODE, 5, vec![h]);
    let tomb = || {
        plain(Body::Tombstone {
            timestamp: 5,
            hashes: h.to_vec(),
            signature: t.signature.to_vec(),
        })
    };
    assert_eq!(
        p.handle(b"n", me, b"p", tomb(), NOW),
        Response::Ack { freed: 1 }
    );
    assert_eq!(
        p.handle(b"n", me, b"p", tomb(), NOW),
        Response::Failure(Refusal::Replayed)
    );
}

fn partner_hosting_node_fragment() -> (NodeService, Id) {
    let mut p = NodeService::new(PARTNER);
    p.partners.insert(
        pk(&NODE),
        PartnerState {
            allowance: 10,
            last_seen: NOW,
            ..Default::default()
        },
    );
    let store = plain(Body::StoreFragment { data: vec![4; 32] });
    p.handle(b"n", Some(pk(&NODE)), b"p", store, NOW);
    (p, hash_sha256(&[4; 32]))
}

fn renew(service: &mut NodeService, seed: &[u8; 32], local: &[u8]) -> SignedGrant {
    let body = Body::RenewGrant {
        grant_pub: pk(&DEVICE).to_vec(),
    };
    match service.handle(b"c", None, local, user_req(seed, body, b"c", local), NOW) {
        Response::GrantIssued(g) => g,
        r => panic!("{r:?}"),
    }
}

#[test]
fn rescue_read_requires_a_grant_from_the_owner_and_is_rate_limited() {
    let (mut p, h) = partner_hosting_node_fragment();
    let g = renew(&mut service_with_user(NODE, 0), &NODE, b"n");
    assert_eq!(
        p.handle(b"c", None, b"p", rescue(&g, b"c", &h), NOW),
        Response::BlockData(vec![4; 32])
    );
    let anonymous = plain(Body::FetchFragment { hash: h.to_vec() });
    assert_eq!(
        p.handle(b"c", None, b"p", anonymous, NOW),
        Response::Failure(Refusal::Unauthorized)
    );
    let limited = (0..300)
        .map(|_| p.handle(b"c", None, b"p", rescue(&g, b"c", &h), NOW))
        .filter(|r| *r == Response::Failure(Refusal::RateLimited))
        .count();
    assert!(limited > 0);
    // Autorisation d'un autre Nœud : ne couvre pas ce propriétaire.
    let other = issue_grant(&NEW_NODE, &pk(&DEVICE), NOW, &[]);
    assert_eq!(
        p.handle(b"c", None, b"p", rescue(&other, b"c", &h), NOW + 10),
        Response::Failure(Refusal::Unauthorized)
    );
}

/// Perte du Nœud et de sa seed : le nouveau Nœud lit par délégation.
#[test]
fn new_node_reads_old_fragments_by_delegation_after_total_loss() {
    let (mut p, h) = partner_hosting_node_fragment();
    let g = issue_grant(&NODE, &pk(&DEVICE), NOW, &[]);
    let d = delegate(&DEVICE, g, &pk(&NEW_NODE), NOW + 1000);
    let mut newn = service_with_user(NEW_NODE, 0);
    let handover = user_req(&NEW_NODE, Body::Delegate(d), b"c", b"nn");
    assert_eq!(
        newn.handle(b"c", None, b"nn", handover, NOW),
        Response::Ack { freed: 0 }
    );
    let fetch = Request {
        credential: Some(Credential::Delegated(newn.delegations[0].clone())),
        body: Body::FetchFragment { hash: h.to_vec() },
    };
    assert_eq!(
        p.handle(b"nn", Some(pk(&NEW_NODE)), b"p", fetch.clone(), NOW),
        Response::BlockData(vec![4; 32])
    );
    assert_eq!(
        p.handle(b"zz", Some(pk(&USER)), b"p", fetch, NOW),
        Response::Failure(Refusal::Unauthorized),
        "seul le Nœud délégué"
    );
}

/// Migration après fuite : pointeur ⇒ anciennes autorisations révoquées,
/// celles du nouveau Nœud couvrent les deux identités.
#[test]
fn migration_pointer_switches_rescue_access_to_the_new_node() {
    let (mut p, h) = partner_hosting_node_fragment();
    let old = issue_grant(&NODE, &pk(&DEVICE), NOW, &[]);
    let mut newn = service_with_user(NEW_NODE, 0);
    newn.previous_node_ids = vec![pk(&NODE)];
    let new = renew(&mut newn, &NEW_NODE, b"nn");
    assert_eq!(
        p.handle(b"c", None, b"p", rescue(&new, b"c", &h), NOW),
        Response::Failure(Refusal::Unauthorized),
        "sans pointeur dans la DHT"
    );
    p.successors.insert(pk(&NODE), pk(&NEW_NODE));
    assert_eq!(
        p.handle(b"c", None, b"p", rescue(&old, b"c", &h), NOW),
        Response::Failure(Refusal::Unauthorized),
        "ancienne clé révoquée"
    );
    assert_eq!(
        p.handle(b"c", None, b"p", rescue(&new, b"c", &h), NOW),
        Response::BlockData(vec![4; 32])
    );
}

#[test]
fn fragments_of_a_silent_node_are_kept_six_months() {
    let (mut p, _) = partner_hosting_node_fragment();
    assert_eq!(p.purge_silent_partners(NOW + 15_552_000 - 1), 0);
    assert_eq!(p.purge_silent_partners(NOW + 15_552_000), 1);
}

#[test]
fn node_id_is_recovered_from_the_noise_peer_id() {
    let kp = libp2p::identity::Keypair::ed25519_from_bytes(NODE).unwrap();
    assert_eq!(node_id_of(&kp.public().to_peer_id()), Some(pk(&NODE)));
}

/// Bout en bout sur TCP local : dépôt, challenge, récupération, trame trop grosse.
#[tokio::test(flavor = "multi_thread")]
async fn two_nodes_exchange_fragments_over_libp2p() {
    let mut ps = NodeService::new(PARTNER);
    ps.partners.insert(
        pk(&NODE),
        PartnerState {
            allowance: 5,
            ..Default::default()
        },
    );
    let clock: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| NOW);
    let listen: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    let partner = BlockServer::start(
        PARTNER,
        listen.clone(),
        Arc::new(Mutex::new(ps)),
        clock.clone(),
    )
    .await
    .unwrap();
    let node = BlockServer::start(
        NODE,
        listen,
        Arc::new(Mutex::new(NodeService::new(NODE))),
        clock,
    )
    .await
    .unwrap();
    let addr = partner.listen_addr().await.unwrap();
    let data = vec![6u8; 65_536];
    let h = hash_sha256(&data);
    let send = |body: Body| node.request(addr.clone(), plain(body));
    let r = send(Body::StoreFragment { data: data.clone() })
        .await
        .unwrap();
    let Response::FragmentReceipt { signature, .. } = r else {
        panic!("{r:?}")
    };
    assert!(verify_receipt(&pk(&PARTNER), &h, &pk(&NODE), &signature));
    let r = send(Body::Challenge {
        hash: h.to_vec(),
        nonce: vec![1; 32],
    })
    .await
    .unwrap();
    assert_eq!(
        r,
        Response::ChallengeResponse(challenge_response(&data, &[1; 32]).to_vec())
    );
    let r = send(Body::FetchFragment { hash: h.to_vec() })
        .await
        .unwrap();
    assert_eq!(r, Response::BlockData(data));
    let r = send(Body::StoreFragment {
        data: vec![0; MAX_MESSAGE_BYTES],
    })
    .await;
    assert!(matches!(r, Err(ExchangeError::Refused(Refusal::TooLarge))));
}
