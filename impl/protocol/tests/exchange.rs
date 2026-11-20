//! Invariants de `protocols.echange-blocs` (partie commune).

use s3m_protocol::exchange::*;

fn pk(s: &[u8; 32]) -> Id {
    ed25519_dalek::SigningKey::from_bytes(s)
        .verifying_key()
        .to_bytes()
}

const NODE: [u8; 32] = [1; 32];
const NEW_NODE: [u8; 32] = [2; 32];
const DEVICE: [u8; 32] = [3; 32];
const NOW: u64 = 1_000_000;

#[test]
fn every_request_and_response_roundtrips() {
    let g = issue_grant(&NODE, &pk(&DEVICE), NOW, &[]);
    let d = delegate(&DEVICE, g.clone(), &pk(&NEW_NODE), NOW + 10);
    let bodies = vec![
        Body::GetBlock { hash: vec![1; 32] },
        Body::PutBlock { data: vec![2; 100] },
        Body::CommitRoot {
            base_root: vec![3; 32],
            new_root: vec![4; 32],
        },
        Body::ReportIncident { hash: vec![5; 32] },
        Body::RenewGrant {
            grant_pub: vec![6; 32],
        },
        Body::Delegate(d.clone()),
        Body::StoreFragment { data: vec![7; 10] },
        Body::Challenge {
            hash: vec![8; 32],
            nonce: vec![9; 32],
        },
        Body::FetchFragment { hash: vec![10; 32] },
        Body::Tombstone {
            timestamp: 7,
            hashes: vec![11; 64],
            signature: vec![12; 64],
        },
        Body::Probe {
            nonce: vec![13; 16],
        },
        Body::ProposePartnership {
            allowance_blocks: 500,
            node_entry: vec![14; 300],
        },
        Body::Attach {
            salt: vec![15; 16],
            sig_pub_user: vec![16; 32],
            vdf_y: vec![17; 100],
            vdf_pi: vec![18; 100],
            signature: vec![19; 64],
        },
    ];
    let creds = [
        None,
        Some(Credential::User {
            user_id: vec![1; 32],
            proof: vec![2; 32],
        }),
        Some(Credential::Rescue {
            grant: g.clone(),
            proof: vec![3; 64],
        }),
        Some(Credential::Delegated(d)),
    ];
    for body in bodies {
        for credential in creds.clone() {
            let r = Request {
                credential,
                body: body.clone(),
            };
            assert_eq!(decode_request(&encode_request(&r)).unwrap(), r);
        }
    }
    for r in [
        Response::Failure(Refusal::RateLimited),
        Response::BlockData(vec![1; 65_536]),
        Response::Stored(vec![2; 32]),
        Response::RootState {
            committed: false,
            current_root: vec![3; 32],
        },
        Response::FragmentReceipt {
            hash: vec![4; 32],
            signature: vec![5; 64],
        },
        Response::ChallengeResponse(vec![6; 32]),
        Response::Ack { freed: 3 },
        Response::GrantIssued(g),
        Response::ProbeReply {
            nonce: vec![1; 16],
            accepting_partners: true,
        },
        Response::PartnershipAnswer { granted_blocks: 42 },
        Response::Attached {
            quota_bytes: 1 << 30,
        },
    ] {
        assert_eq!(decode_response(&encode_response(&r)).unwrap(), r);
    }
}

#[test]
fn oversize_foreign_and_unknown_version_messages_are_rejected() {
    assert_eq!(
        decode_request(&vec![0; MAX_MESSAGE_BYTES + 1]),
        Err(Refusal::TooLarge)
    );
    let resp = encode_response(&Response::Ack { freed: 0 });
    assert_eq!(
        decode_request(&resp),
        Err(Refusal::Malformed),
        "identifiant BRSP ≠ BREQ"
    );
    let mut req = encode_request(&Request {
        credential: None,
        body: Body::GetBlock { hash: vec![] },
    });
    // Message tronqué.
    req.truncate(8);
    assert_eq!(decode_request(&req), Err(Refusal::Malformed));
}

#[test]
fn connector_proof_is_bound_to_both_peers_and_k_attach() {
    let k = [9; 32];
    let p = connector_proof(&k, b"conn", b"node");
    assert!(verify_connector_proof(&k, b"conn", b"node", &p));
    assert!(!verify_connector_proof(&k, b"other", b"node", &p));
    assert!(!verify_connector_proof(&k, b"conn", b"other", &p));
    assert!(!verify_connector_proof(&[8; 32], b"conn", b"node", &p));
}

#[test]
fn grant_is_signed_by_issuer_and_expires_after_six_months() {
    let sg = issue_grant(&NODE, &pk(&DEVICE), NOW, &[[7; 32]]);
    let g = open_grant(&sg, NOW).unwrap();
    assert_eq!(g.issuer_node_id, pk(&NODE));
    assert_eq!(g.expires_at, NOW + 15_552_000);
    assert_eq!(g.covered_node_ids, vec![[7; 32]]);
    assert_eq!(
        open_grant(&sg, NOW + 15_552_000),
        Err(Refusal::Unauthorized)
    );
    let mut forged = sg.clone();
    let n = forged.grant.len();
    forged.grant[n - 1] ^= 1;
    assert!(open_grant(&forged, NOW).is_err());
}

#[test]
fn rescue_session_proof_is_bound_to_the_connection() {
    let sg = issue_grant(&NODE, &pk(&DEVICE), NOW, &[]);
    let proof = rescue_session_proof(&DEVICE, b"me", b"partner");
    let c = Credential::Rescue {
        grant: sg.clone(),
        proof,
    };
    assert!(authorize_rescue(Some(&c), b"me", None, b"partner", NOW).is_ok());
    assert_eq!(
        authorize_rescue(Some(&c), b"thief", None, b"partner", NOW),
        Err(Refusal::Unauthorized)
    );
    let wrong = Credential::Rescue {
        grant: sg,
        proof: rescue_session_proof(&[4; 32], b"me", b"partner"),
    };
    assert_eq!(
        authorize_rescue(Some(&wrong), b"me", None, b"partner", NOW),
        Err(Refusal::Unauthorized)
    );
    assert_eq!(
        authorize_rescue(None, b"me", None, b"partner", NOW),
        Err(Refusal::Unauthorized)
    );
}

/// Perte du Nœud sans seed : la délégation suffit, sans aucune clé de l'ancien Nœud.
#[test]
fn delegation_lets_only_the_delegate_node_read_within_the_grant_lifetime() {
    let sg = issue_grant(&NODE, &pk(&DEVICE), NOW, &[]);
    let d = delegate(&DEVICE, sg.clone(), &pk(&NEW_NODE), NOW + 100);
    let c = Credential::Delegated(d);
    let g = authorize_rescue(Some(&c), b"x", Some(&pk(&NEW_NODE)), b"p", NOW).unwrap();
    assert!(covers(&g, &pk(&NODE), &|_| None));
    assert!(authorize_rescue(Some(&c), b"x", Some(&pk(&[5; 32])), b"p", NOW).is_err());
    assert!(authorize_rescue(Some(&c), b"x", None, b"p", NOW).is_err());
    assert!(authorize_rescue(Some(&c), b"x", Some(&pk(&NEW_NODE)), b"p", NOW + 100).is_err());
    let too_long = delegate(&DEVICE, sg, &pk(&NEW_NODE), NOW + 15_552_001);
    assert!(open_delegation(&too_long, NOW).is_err());
}

/// Migration après fuite : le pointeur révoque l'ancienne clé et ouvre
/// l'accès aux autorisations du nouveau Nœud qui couvrent l'ancien.
#[test]
fn migration_pointer_revokes_old_grants_and_extends_new_ones() {
    let (old, new) = (pk(&NODE), pk(&NEW_NODE));
    let old_grant = open_grant(&issue_grant(&NODE, &pk(&DEVICE), NOW, &[]), NOW).unwrap();
    let new_grant = open_grant(&issue_grant(&NEW_NODE, &pk(&DEVICE), NOW, &[old]), NOW).unwrap();
    let none = |_: &Id| None;
    let migrated = move |o: &Id| (*o == old).then_some(new);
    assert!(covers(&old_grant, &old, &none));
    assert!(!covers(&old_grant, &old, &migrated), "révoquée");
    assert!(
        !covers(&new_grant, &old, &none),
        "pas de pointeur : pas de couverture"
    );
    assert!(covers(&new_grant, &old, &migrated));
    assert!(covers(&new_grant, &new, &none));
    let elsewhere = move |o: &Id| (*o == old).then_some([0xEE; 32]);
    assert!(
        !covers(&new_grant, &old, &elsewhere),
        "pointeur vers un autre Nœud"
    );
}

#[test]
fn receipts_bind_partner_hash_and_depositor() {
    let s = sign_receipt(&NODE, &[1; 32], &[2; 32]);
    assert!(verify_receipt(&pk(&NODE), &[1; 32], &[2; 32], &s));
    assert!(!verify_receipt(&pk(&NODE), &[1; 32], &[3; 32], &s));
    assert!(!verify_receipt(&pk(&NEW_NODE), &[1; 32], &[2; 32], &s));
}

#[test]
fn rescue_rate_is_bounded_per_grant() {
    let mut l = RescueLimiter::default();
    let k = [1; 32];
    assert_eq!((0..300).filter(|_| l.allow(&k, 10)).count(), 256);
    assert!(l.allow(&[2; 32], 10), "seau distinct par autorisation");
    assert_eq!((0..100).filter(|_| l.allow(&k, 11)).count(), 64);
}
