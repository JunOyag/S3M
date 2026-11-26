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
    // Toute requête de son Connecteur compte comme activité
    // (`protocols.partenariat-automatique#inactivite`).
    assert_eq!(s.last_active.values().copied().collect::<Vec<_>>(), vec![NOW]);
    assert_eq!(
        call(&mut s, Body::PutBlock { data: vec![2; 60] }),
        Response::Failure(Refusal::QuotaExceeded)
    );
    let commit = |base: u8, new: u8, seal: Vec<u8>| Body::CommitRoot {
        base_root: vec![base; 32],
        new_root: vec![new; 32],
        root_seal: seal,
    };
    let state = |committed: bool, root: u8, seal: Vec<u8>| Response::RootState {
        committed,
        current_root: vec![root; 32],
        quota_bytes: 100,
        used_bytes: 60,
        current_root_seal: seal,
    };
    // Aucune racine connue (Utilisateur repris) : une base ancienne est
    // acceptée telle quelle, une seule fois ; le descripteur est gardé.
    assert_eq!(call(&mut s, commit(9, 5, vec![1; 47])), state(true, 5, vec![1; 47]));
    assert_eq!(call(&mut s, commit(0, 6, vec![2; 47])), state(false, 5, vec![1; 47]));
    // Lecture neutre sans descripteur : gardé ; racine changée sans
    // descripteur (ancien Connecteur) : effacé.
    assert_eq!(call(&mut s, commit(5, 5, vec![])), state(true, 5, vec![1; 47]));
    assert_eq!(call(&mut s, commit(5, 7, vec![])), state(true, 7, vec![]));
    // Historique (`protocols.historique-versions`) : la version remplacée,
    // son descripteur et ses dates ; purge à la demande.
    assert_eq!(
        call(&mut s, Body::ListRoots),
        Response::RootList {
            versions: vec![s3m_protocol::exchange::RootVersion {
                root: vec![5; 32],
                root_seal: vec![1; 47],
                valid_from: NOW,
                replaced_at: NOW,
            }],
            retention_s: 30 * 86_400,
        }
    );
    // Sans 2FA : purge différée de 72 h (`securite.incidents-compromissions#2fa`).
    assert!(matches!(call(&mut s, Body::PurgeRoots { before: 0, code: String::new() }), Response::Deferred { .. }));
    s.run_due_ops(NOW + s3m_node::user2fa::DEFER_S);
    assert_eq!(
        call(&mut s, Body::ListRoots),
        Response::RootList { versions: vec![], retention_s: 30 * 86_400 }
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
            quota: 1,
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
        "quota atteint"
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

/// Échange sur l'offre (`node.PartnerAccount#equilibre`) : jusqu'à Q
/// fragments quoi que le Nœud héberge en retour ; doublon non recompté ;
/// quota non négocié = confiance initiale.
#[test]
fn offer_quota_bounds_deposits_whatever_is_hosted_in_return() {
    let mut p = NodeService::new(PARTNER);
    p.partners.insert(
        pk(&NODE),
        PartnerState {
            quota: 2,
            ..Default::default()
        },
    );
    let me = Some(pk(&NODE));
    let store = |p: &mut NodeService, b: u8| {
        p.handle(
            b"n",
            me,
            b"p",
            plain(Body::StoreFragment { data: vec![b; 40] }),
            NOW,
        )
    };
    assert!(matches!(store(&mut p, 1), Response::FragmentReceipt { .. }));
    assert!(
        matches!(store(&mut p, 1), Response::FragmentReceipt { .. }),
        "doublon"
    );
    assert!(matches!(store(&mut p, 2), Response::FragmentReceipt { .. }));
    assert_eq!(store(&mut p, 3), Response::Failure(Refusal::QuotaExceeded));
    assert_eq!(p.partners[&pk(&NODE)].ledger.hosted_by_partner, 2);
    // Quota pas encore négocié : confiance initiale.
    p.partner_policy.trust_initial_blocks = 3;
    p.partners.get_mut(&pk(&NODE)).unwrap().quota = 0;
    assert!(matches!(store(&mut p, 3), Response::FragmentReceipt { .. }));
    assert_eq!(store(&mut p, 4), Response::Failure(Refusal::QuotaExceeded));
}

/// Négociation (`node.PartnerAccount#quota`) : le plus petit des deux,
/// jamais sous ce que le Nœud stocke déjà chez le demandeur.
#[test]
fn quota_negotiation_takes_the_smaller_promise_never_below_own_usage() {
    let mut p = NodeService::new(PARTNER);
    p.partner_policy.offer_bytes = 32 * 1_000 * 65_536; // q = 1 000
    p.partner_policy.trust_initial_blocks = 400;
    p.partners.insert(pk(&NODE), PartnerState::default());
    let propose = |p: &mut NodeService, allowance: u64| {
        p.handle(
            b"n",
            Some(pk(&NODE)),
            b"p",
            plain(Body::ProposePartnership {
                allowance_blocks: allowance,
                node_entry: vec![],
            }),
            NOW,
        )
    };
    let granted = |r: Response| match r {
        Response::PartnershipAnswer { granted_blocks } => granted_blocks,
        r => panic!("{r:?}"),
    };
    assert_eq!(granted(propose(&mut p, 5_000)), 400, "confiance");
    assert_eq!(granted(propose(&mut p, 100)), 100, "offre du demandeur");
    assert_eq!(p.partners[&pk(&NODE)].quota, 100);
    p.partners
        .get_mut(&pk(&NODE))
        .unwrap()
        .ledger
        .hosted_for_partner = 250;
    assert_eq!(granted(propose(&mut p, 100)), 250, "pas sous l'usage");
    p.partners.get_mut(&pk(&NODE)).unwrap().trust = 4_000;
    assert_eq!(granted(propose(&mut p, 5_000)), 1_000, "offre / partenaires");
}

/// Manquements et confiance (`node.PartnerAccount#confiance`).
#[test]
fn failures_suspend_and_reset_trust_which_doubles_after_a_clean_period() {
    let mut p = NodeService::new(PARTNER);
    p.partner_policy.filler = false;
    p.partner_policy.trust_initial_blocks = 100;
    p.partner_policy.trust_period_s = 1_000;
    let n = pk(&NODE);
    p.partners.insert(n, PartnerState::default());
    p.ramp_trust(NOW);
    // Période propre avec contrôle réussi : doublement.
    p.partners.get_mut(&n).unwrap().proved_at = NOW + 10;
    p.ramp_trust(NOW + 1_000);
    assert_eq!(p.partner_policy.trust_of(&p.partners[&n]), 200);
    // Sans contrôle réussi : inchangée.
    p.ramp_trust(NOW + 2_000);
    assert_eq!(p.partner_policy.trust_of(&p.partners[&n]), 200);
    // Manquement : confiance initiale, placements suspendus.
    assert_eq!(p.record_failure(&n, NOW + 2_100), 1);
    assert_eq!(p.partner_policy.trust_of(&p.partners[&n]), 100);
    assert!(p.suspended(NOW + 2_500).contains(&n));
    assert!(!p.suspended(NOW + 3_100).contains(&n));
    assert_eq!(p.record_failure(&n, NOW + 2_200), 2);
    assert_eq!(p.record_failure(&n, NOW + 2_300), MAX_FAILURES);
    // Période suivante : manquements remis à zéro, pas de doublement.
    p.partners.get_mut(&n).unwrap().proved_at = NOW + 2_900;
    p.ramp_trust(NOW + 3_100);
    assert_eq!(p.partners[&n].failures, 0);
    assert_eq!(p.partner_policy.trust_of(&p.partners[&n]), 100);
}

#[test]
fn subnets_are_slash_24_and_slash_48() {
    assert_eq!(subnet("192.168.13.235").as_deref(), Some("192.168.13"));
    assert_eq!(subnet("2001:db8:1:2::5").as_deref(), Some("2001:db8:1"));
    assert_eq!(subnet("pas une ip"), None);
}

fn partner_hosting_node_fragment() -> (NodeService, Id) {
    let mut p = NodeService::new(PARTNER);
    p.partners.insert(
        pk(&NODE),
        PartnerState {
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
            ledger: s3m_node::tombstones::PartnerLedger {
                hosted_for_partner: 5,
                ..Default::default()
            },
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

/// Rotation d'identité (`securite.incidents-compromissions#rotation-user`) :
/// compte, blocs et racine passent à la nouvelle identité ; l'ancienne est
/// révoquée et ne peut plus se rattacher.
#[test]
fn rotation_moves_the_account_and_revokes_the_old_identity() {
    let mut s = service_with_user(NODE, 1 << 20);
    let call = |s: &mut NodeService, body: Body| {
        s.handle(b"c", None, b"n", user_req(&NODE, body, b"c", b"n"), NOW)
    };
    let h = hash_sha256(&[1; 60]);
    call(&mut s, Body::PutBlock { data: vec![1; 60] });
    call(
        &mut s,
        Body::CommitRoot { base_root: vec![0; 32], new_root: vec![5; 32], root_seal: vec![1; 47] },
    );
    let new = [0x77; 32];
    assert!(matches!(
        call(&mut s, Body::RotateUser { new_user_id: new.to_vec(), new_salt: vec![9; 16], code: String::new() }),
        Response::Deferred { .. }
    ));
    assert!(s.users.contains_key(&pk(&USER)), "rien avant l'échéance");
    assert_eq!(s.run_due_ops(NOW + s3m_node::user2fa::DEFER_S), 1);
    let acc = &s.users[&new];
    assert_eq!((acc.root, acc.salt.clone()), ([5; 32], vec![9; 16]));
    assert!(!s.users.contains_key(&pk(&USER)));
    assert!(s.revoked_users.contains(&pk(&USER)));
    assert_eq!(s.store.get(s3m_node::chunk_store::Space::UserBlock, &h).unwrap().0, new);
    assert!(s.root_seals.is_empty(), "descripteur de l'ancienne clé oublié");
    assert_eq!(s.renamed_users, vec![(pk(&USER), new)]);
    // L'ancienne identité n'a plus accès, même par un nouveau rattachement.
    assert_eq!(
        call(&mut s, Body::GetBlock { hash: h.to_vec() }),
        Response::Failure(Refusal::Unauthorized)
    );
}

/// Maintenance déclarée par un partenaire : tolérée 24 h au plus, une fois
/// par période de 7 jours (`node.PartnerAccount#manquements`).
#[test]
fn a_partner_maintenance_is_tolerated_once_a_week_for_a_day() {
    let mut s = NodeService::new(NODE);
    let p = [0x55; 32];
    s.partners.insert(p, PartnerState::default());
    let t0 = NOW;
    // Réponses toutes les 30 min : tolérées pendant 24 h.
    let mut t = t0;
    while t <= t0 + MAINTENANCE_MAX_S {
        assert!(s.maintenance_tolerated(&p, t), "à {}", t - t0);
        t += 1_800;
    }
    assert!(!s.maintenance_tolerated(&p, t), "au-delà de 24 h");
    // Nouvel épisode dans la même semaine : manquement.
    assert!(!s.maintenance_tolerated(&p, t0 + 3 * 86_400));
    // Une semaine plus tard : de nouveau toléré.
    assert!(s.maintenance_tolerated(&p, t0 + MAINTENANCE_PERIOD_S + 1));
}

/// 2FA (`securite.incidents-compromissions#2fa`) : sans code, changer
/// d'identité est refusé ; un code TOTP ou de secours (à usage unique)
/// l'autorise ; sans 2FA, l'opération est différée et annulable.
#[test]
fn twofa_guards_identity_rotation_and_deferred_operations_can_be_cancelled() {
    use s3m_node::admin::hotp;
    use s3m_node::user2fa::{recovery_hash, DEFER_S};
    let mut s = service_with_user(NODE, 1 << 20);
    let call = |s: &mut NodeService, body: Body| {
        s.handle(b"c", None, b"n", user_req(&NODE, body, b"c", b"n"), NOW)
    };
    // Sans 2FA : différé, prévenu, annulable.
    let r = call(&mut s, Body::RotateUser { new_user_id: vec![0x61; 32], new_salt: vec![1; 16], code: String::new() });
    let Response::Deferred { id, due_at } = r else { panic!("{r:?}") };
    assert_eq!(due_at, NOW + DEFER_S);
    assert_eq!(s.channel.outbox.sent.len(), 1, "appareils prévenus");
    let Response::PendingList { twofa, ops } = call(&mut s, Body::ListPending) else { panic!() };
    assert!(!twofa && ops.len() == 1 && ops[0].kind == "changement d'identité");
    call(&mut s, Body::CancelPending { id });
    assert_eq!(s.run_due_ops(NOW + DEFER_S), 0, "annulé");
    // Activation : le premier code doit être bon.
    let secret = [7u8; 20];
    let code = |t: u64| format!("{:06}", hotp(&secret, t / 30, 6));
    let set = |c: String| Body::Set2fa { secret: secret.to_vec(), code: c, recovery: recovery_hash("ABCD-EFGH").to_vec(), current: String::new() };
    assert_eq!(call(&mut s, set("000000".into())), Response::Failure(Refusal::Unauthorized));
    assert_eq!(call(&mut s, set(code(NOW))), Response::Ack { freed: 0 });
    // Avec 2FA : sans code, refus (le pirate ne peut ni différer ni changer).
    let rot = |c: &str| Body::RotateUser { new_user_id: vec![0x62; 32], new_salt: vec![2; 16], code: c.into() };
    assert_eq!(call(&mut s, rot("")), Response::Failure(Refusal::Unauthorized));
    assert_eq!(call(&mut s, Body::PurgeRoots { before: 0, code: String::new() }), Response::Failure(Refusal::Unauthorized));
    // Code de secours : accepté une seule fois.
    assert_eq!(call(&mut s, rot("abcd efgh")), Response::Ack { freed: 0 });
    assert!(s.users.contains_key(&[0x62; 32]) && s.twofa.contains_key(&[0x62; 32]), "le 2FA suit le compte");
    assert!(s.twofa[&[0x62; 32]].recovery.is_empty());
}

/// Nouvel appareil (U4) : le premier est enregistré sans bruit, un second
/// est annoncé à l'Utilisateur ; un appareil connu ne l'est plus.
#[test]
fn a_new_device_is_announced_to_the_user() {
    let mut s = service_with_user(NODE, 1 << 20);
    let call = |s: &mut NodeService, from: &[u8]| {
        s.handle(from, None, b"n", user_req(&NODE, Body::ListPending, from, b"n"), NOW)
    };
    call(&mut s, b"appareil-1");
    call(&mut s, b"appareil-1");
    assert_eq!(s.channel.outbox.sent.len(), 0, "premier appareil : rien");
    call(&mut s, b"appareil-2");
    assert_eq!(s.channel.outbox.sent.len(), 1, "nouvel appareil annoncé");
    call(&mut s, b"appareil-2");
    assert_eq!(s.channel.outbox.sent.len(), 1);
    // Identifiant refusé : rien d'enregistré.
    s.handle(b"intrus", None, b"n", user_req(&NODE, Body::ListPending, b"autre", b"n"), NOW);
    assert_eq!(s.devices[&pk(&USER)].len(), 2);
}
