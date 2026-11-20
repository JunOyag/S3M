//! Partenariats et rattachements automatiques
//! (`protocols.partenariat-automatique`), géolocalisation de la carte.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use p2p_storage_core::k_attach::derive_k_attach_as_user;
use p2p_storage_core::keys::{derive_sig_priv_user, derive_sig_pub_user};
use p2p_storage_core::vdf::VdfProof;
use p2p_storage_node::dht_directory::{DhtConfig, DhtNode};
use p2p_storage_node::dispersal_engine::DispersalState;
use p2p_storage_node::exchange::*;
use p2p_storage_node::geo::{is_private, year_month, Geo};
use p2p_storage_node::partnering::*;
use p2p_storage_node::publish::{publish_if_due, NodeEntryState};
use p2p_storage_protocol::entries::{node_entry_envelope, NodeEntryParams};
use p2p_storage_protocol::exchange::*;

const A: [u8; 32] = [0x10; 32];
const B: [u8; 32] = [0x20; 32];
const USER: [u8; 32] = [0x40; 32];
const NOW: u64 = 1_000_000;

fn pk(s: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(s)
        .verifying_key()
        .to_bytes()
}

fn proof() -> VdfProof {
    VdfProof {
        y: vec![1; 100],
        pi: vec![2; 100],
    }
}

fn permissive() -> VdfCheck {
    Arc::new(|_, _| true)
}

fn entry(seed: &[u8; 32]) -> Vec<u8> {
    node_entry_envelope(
        seed,
        &NodeEntryParams {
            ip: "203.0.113.5",
            port: 4002,
            timestamp: NOW,
            proof: &proof(),
            pub_node_recovery: &[0; 32],
            snapshot_pointer: None,
            addrs: &[],
        },
        &[1; 12],
    )
    .unwrap()
}

#[test]
fn score_combines_reliability_availability_and_speed() {
    let cfg = PartneringConfig::default();
    let fresh = Peer::default();
    let s = score(&cfg, &fresh, 0, 0);
    assert_eq!((s.reliability, s.availability, s.speed), (0.5, 0.5, 0.5));
    let good = Peer {
        availability: 1.0,
        latency_ms: 50.0,
        probes: 10,
        answered: 10,
        ..Default::default()
    };
    let s = score(&cfg, &good, 98, 0);
    assert!(s.total > 0.95, "{s:?}");
    let slow = Peer {
        availability: 0.2,
        latency_ms: 2_000.0,
        probes: 10,
        answered: 2,
        ..Default::default()
    };
    let s = score(&cfg, &slow, 1, 9);
    assert!(s.total < cfg.exit_threshold, "{s:?}");
    assert!((s.speed - 0.1).abs() < 1e-9);
}

#[test]
fn proposals_are_accepted_within_policy_and_verified_entries_only() {
    let mut b = NodeService::new(B);
    b.vdf = Some(permissive());
    b.partner_policy = PartnerPolicy {
        accept: true,
        max_partners: 1,
        max_allowance_blocks: 300,
    };
    let propose = |allowance, entry: Vec<u8>| Request {
        credential: None,
        body: Body::ProposePartnership {
            allowance_blocks: allowance,
            node_entry: entry,
        },
    };
    // Entrée d'un autre Nœud que le demandeur : refus.
    let r = b.handle(
        b"a",
        Some(pk(&A)),
        b"b",
        propose(500, entry(&[0x30; 32])),
        NOW,
    );
    assert_eq!(r, Response::PartnershipAnswer { granted_blocks: 0 });
    let r = b.handle(b"a", Some(pk(&A)), b"b", propose(500, entry(&A)), NOW);
    assert_eq!(
        r,
        Response::PartnershipAnswer {
            granted_blocks: 300
        },
        "plafonné"
    );
    assert_eq!(b.partners[&pk(&A)].allowance, 300);
    assert_eq!(b.new_partners.len(), 1);
    assert_eq!(b.new_partners[0].0, pk(&A));
    assert!(b.new_partners[0].1[0].starts_with("/ip4/203.0.113.5/tcp/4002/p2p/"));
    let r = b.handle(b"a", Some(pk(&A)), b"b", propose(500, entry(&A)), NOW);
    assert_eq!(
        r,
        Response::PartnershipAnswer {
            granted_blocks: 300
        },
        "idempotent"
    );
    let c = [0x30; 32];
    let r = b.handle(b"c", Some(pk(&c)), b"b", propose(10, entry(&c)), NOW);
    assert_eq!(
        r,
        Response::PartnershipAnswer { granted_blocks: 0 },
        "plein"
    );
    let probe = Request {
        credential: None,
        body: Body::Probe { nonce: vec![7; 16] },
    };
    assert_eq!(
        b.handle(b"x", None, b"b", probe, NOW),
        Response::ProbeReply {
            nonce: vec![7; 16],
            accepting_partners: false
        }
    );
    let mut b2 = NodeService::new(B);
    b2.vdf = Some(permissive());
    b2.blacklisted.insert(pk(&A));
    let r = b2.handle(b"a", Some(pk(&A)), b"b", propose(5, entry(&A)), NOW);
    assert_eq!(
        r,
        Response::PartnershipAnswer { granted_blocks: 0 },
        "liste noire"
    );
}

fn attach_req(user: &[u8; 32], salt: [u8; 16], sig_seed: Option<[u8; 32]>) -> Request {
    let pub_user = pk(user);
    let k = derive_k_attach_as_user(user, &pk(&B), &salt).unwrap();
    let sig_priv = sig_seed.unwrap_or_else(|| derive_sig_priv_user(user, &pub_user).unwrap());
    let sig_pub = derive_sig_pub_user(&sig_priv);
    Request {
        credential: Some(Credential::User {
            user_id: pub_user.to_vec(),
            proof: connector_proof(&k, b"c", b"n").to_vec(),
        }),
        body: Body::Attach {
            salt: salt.to_vec(),
            sig_pub_user: sig_pub.to_vec(),
            vdf_y: vec![1; 100],
            vdf_pi: vec![2; 100],
            signature: attach_signature(&sig_priv, &pub_user, &pk(&B)),
        },
    }
}

#[test]
fn users_attach_automatically_within_quota_budget_with_one_use_vdf_identities() {
    let mut b = NodeService::new(B);
    b.vdf = Some(permissive());
    let r = b.handle(b"c", None, b"n", attach_req(&USER, [1; 16], None), NOW);
    assert_eq!(
        r,
        Response::Failure(Refusal::Unauthorized),
        "désactivé par défaut"
    );
    b.attach_policy = AttachPolicy {
        enabled: true,
        quota_bytes: 1_000,
        max_users: 5,
        budget_bytes: 2_500,
    };
    let r = b.handle(b"c", None, b"n", attach_req(&USER, [1; 16], None), NOW);
    assert_eq!(r, Response::Attached { quota_bytes: 1_000 });
    assert!(b.auto_attached.contains(&pk(&USER)));
    assert_eq!(b.users[&pk(&USER)].salt, vec![1; 16]);
    // Déjà rattaché : idempotent.
    let r = b.handle(b"c", None, b"n", attach_req(&USER, [1; 16], None), NOW);
    assert_eq!(r, Response::Attached { quota_bytes: 1_000 });
    // Même identité VDF pour un autre Utilisateur : refus.
    let shared_sig = derive_sig_priv_user(&USER, &pk(&USER)).unwrap();
    let r = b.handle(
        b"c",
        None,
        b"n",
        attach_req(&[0x41; 32], [2; 16], Some(shared_sig)),
        NOW,
    );
    assert_eq!(r, Response::Failure(Refusal::Unauthorized));
    // Budget : 2 500 o pour des quotas de 1 000 o.
    let r = b.handle(
        b"c",
        None,
        b"n",
        attach_req(&[0x42; 32], [3; 16], None),
        NOW,
    );
    assert_eq!(r, Response::Attached { quota_bytes: 1_000 });
    let r = b.handle(
        b"c",
        None,
        b"n",
        attach_req(&[0x43; 32], [4; 16], None),
        NOW,
    );
    assert_eq!(r, Response::Failure(Refusal::QuotaExceeded));
    // Preuve d'identité calculée pour une autre connexion : refus.
    let stolen = attach_req(&[0x44; 32], [5; 16], None);
    assert_eq!(
        b.handle(b"x", None, b"n", stolen, NOW),
        Response::Failure(Refusal::Unauthorized)
    );
    // VDF invalide : refus.
    b.vdf = Some(Arc::new(|_, _| false));
    let r = b.handle(
        b"c",
        None,
        b"n",
        attach_req(&[0x45; 32], [6; 16], None),
        NOW,
    );
    assert_eq!(r, Response::Failure(Refusal::Unauthorized));
}

#[test]
fn geolocation_skips_private_addresses_and_dates_are_civil() {
    assert!(is_private(&"192.168.1.2".parse().unwrap()));
    assert!(is_private(&"100.64.0.1".parse().unwrap()));
    assert!(!is_private(&"203.0.113.5".parse().unwrap()));
    assert_eq!(Geo::none().locate("8.8.8.8"), None);
    assert_eq!(year_month(0), (1970, 1));
    assert_eq!(year_month(1_795_174_743), (2026, 11));
    assert_eq!(year_month(951_782_400), (2000, 2)); // 29/02/2000
}

type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// Deux Nœuds réels : A découvre B dans la DHT, le teste, lui propose un
/// partenariat ; B l'accepte. Puis B devient mauvais : retrait, puis fin.
#[tokio::test(flavor = "multi_thread")]
async fn nodes_discover_score_and_partner_then_retire_weak_partners() {
    let clock: Clock = Arc::new(|| NOW);
    let listen: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    let start_dht = |seed, boot| {
        let clock = clock.clone();
        let listen = listen.clone();
        async move {
            DhtNode::start(DhtConfig {
                node_seed: seed,
                listen,
                bootstrap: boot,
                vdf: Arc::new(|_, _| Ok(true)),
                clock,
            })
            .await
            .unwrap()
        }
    };
    let dht_b = start_dht(B, vec![]).await;
    let dht_a = start_dht(A, vec![dht_b.listen_addr().await.unwrap()]).await;

    let mut sb = NodeService::new(B);
    sb.vdf = Some(permissive());
    let sb = Arc::new(Mutex::new(sb));
    let server_b = BlockServer::start(B, listen.clone(), sb.clone(), clock.clone())
        .await
        .unwrap();
    let port_b = match server_b.listen_addr().await.unwrap().iter().nth(1) {
        Some(libp2p::multiaddr::Protocol::Tcp(p)) => p,
        _ => panic!(),
    };
    let sa = Arc::new(Mutex::new(NodeService::new(A)));
    let server_a = BlockServer::start(A, listen, sa.clone(), clock.clone())
        .await
        .unwrap();

    // Entrées Node publiées (preuve factice, DHT permissive).
    let st = Mutex::new(NodeEntryState::default());
    publish_if_due(
        &dht_b,
        &B,
        &pk(&B),
        &[0; 32],
        ("127.0.0.1".into(), port_b),
        &proof(),
        None,
        &st,
        NOW,
    )
    .await;
    let sa_entry = Mutex::new(NodeEntryState::default());
    publish_if_due(
        &dht_a,
        &A,
        &pk(&A),
        &[0; 32],
        ("127.0.0.1".into(), 1),
        &proof(),
        None,
        &sa_entry,
        NOW,
    )
    .await;

    let cfg = PartneringConfig {
        retire_after_s: 100,
        ..Default::default()
    };
    let addrs = Mutex::new(HashMap::new());
    let net = Net {
        server: &server_a,
        dht: &dht_a,
        addrs: &addrs,
        own_entry: sa_entry.lock().unwrap().last_envelope.clone(),
    };
    let mut state = DispersalState::default();
    let r = run_partnering(&sa, &mut state, &net, &cfg, 1, NOW).await;
    assert_eq!(
        (r.discovered, r.accepted),
        (1, 1),
        "{r:?} {:?}",
        state.partnering.events
    );
    assert!(sa.lock().unwrap().partners.contains_key(&pk(&B)));
    assert!(addrs.lock().unwrap().contains_key(&pk(&B)));
    assert!(
        sb.lock().unwrap().partners.contains_key(&pk(&A)),
        "B a accepté"
    );
    let peer = &state.partnering.peers[&hex::encode(pk(&B))];
    assert_eq!(peer.status, "partenaire");
    assert!(peer.availability > 0.9 && peer.answered == 1);

    // B côté démon : l'adresse du demandeur est retenue.
    let addrs_b = Mutex::new(HashMap::new());
    let net_b = Net {
        server: &server_b,
        dht: &dht_b,
        addrs: &addrs_b,
        own_entry: None,
    };
    let mut state_b = DispersalState::default();
    let cfg_off = PartneringConfig {
        enabled: false,
        ..Default::default()
    };
    run_partnering(&sb, &mut state_b, &net_b, &cfg_off, 1, NOW).await;
    assert!(addrs_b.lock().unwrap().contains_key(&pk(&A)));

    // B se dégrade : score sous le seuil de retrait, puis retrait, puis fin.
    {
        let p = state
            .partnering
            .peers
            .get_mut(&hex::encode(pk(&B)))
            .unwrap();
        p.availability = 0.0;
        p.latency_ms = 5_000.0;
    }
    state.upkeep.pos_fail.insert(hex::encode(pk(&B)), 20);
    assert!(
        excluded(&cfg, &state).contains(&pk(&B)),
        "plus de nouveaux fragments"
    );
    let r = run_partnering(&sa, &mut state, &net, &cfg, 1, NOW + 1).await;
    assert_eq!(r.retiring, 0, "pas encore 100 s sous le seuil");
    let r = run_partnering(&sa, &mut state, &net, &cfg, 1, NOW + 200).await;
    assert_eq!((r.retiring, r.ended), (1, 1), "{r:?}");
    assert!(!sa.lock().unwrap().partners.contains_key(&pk(&B)));
    assert_eq!(
        state.partnering.peers[&hex::encode(pk(&B))].status,
        "terminé"
    );
}
