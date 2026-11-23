//! Dispersion automatique (`protocols.dispersion-transactionnelle`,
//! orchestration) : un Nœud, quatre partenaires réels sur TCP local, puis
//! reconstruction de toutes les données depuis la seule DHT et la parité
//! des partenaires (perte totale du Nœud).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use s3m_core::erasure::{padding_block, reconstruct_data};
use s3m_core::k_attach::derive_k_attach_as_node;
use s3m_core::k_dispersal::derive_k_dispersal_content;
use s3m_core::symmetric_suite::hash_sha256;
use s3m_core::version::CURRENT_HEADER;
use s3m_node::chunk_store::Space;
use s3m_node::dht_directory::{DhtConfig, DhtNode};
use s3m_node::dispersal_engine::*;
use s3m_node::exchange::{BlockServer, NodeService, PartnerState, UserAccount};
use s3m_protocol::dht::dispersal_dht_key;
use s3m_protocol::dispersal::*;
use s3m_protocol::index::open_index_node;

const NODE: [u8; 32] = [0x10; 32];
const USER: [u8; 32] = [0x40; 32];
const SALT: [u8; 16] = [7; 16];

fn pk(s: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(s)
        .verifying_key()
        .to_bytes()
}

fn block(seed: u8) -> Vec<u8> {
    (0..65_536u32)
        .map(|i| (i as u8).wrapping_mul(seed).wrapping_add(seed))
        .collect()
}

type Partners = Vec<Arc<Mutex<NodeService>>>;

/// Reconstruit les k blocs de données d'un stripe depuis la parité seule.
fn rebuild(stripe: &StripeDesc, partners: &Partners, coef: usize) -> Vec<Vec<u8>> {
    let k = stripe.k as usize;
    let mut shards: Vec<Option<Vec<u8>>> = vec![None; k + k * coef];
    for b in &stripe.blocks {
        let i = b.index as usize;
        if b.is_padding {
            shards[i] = Some(padding_block());
        } else if i >= k {
            shards[i] = partners
                .iter()
                .find_map(|p| p.lock().unwrap().store.get(Space::Fragment, &b.hash))
                .map(|(_, d)| d);
        }
    }
    reconstruct_data(shards, k, coef).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn node_disperses_publishes_and_data_survives_total_node_loss() {
    let cfg = EngineConfig {
        k: 2,
        coef: 2,
        idle_timeout_s: 100,
        grace_s: 0,
        min_confirmations: 0,
    };
    let clock: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| 1_000);
    let listen: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();

    // Quatre partenaires qui acceptent les fragments du Nœud.
    let mut partners: Partners = Vec::new();
    let mut servers = Vec::new();
    let mut addrs = HashMap::new();
    let mut service = NodeService::new(NODE);
    for i in 0..4u8 {
        let seed = [0x60 + i; 32];
        let mut ps = NodeService::new(seed);
        ps.partners.insert(
            pk(&NODE),
            PartnerState {
                ledger: s3m_node::tombstones::PartnerLedger {
                    hosted_for_partner: 1_000,
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        let ps = Arc::new(Mutex::new(ps));
        let s = BlockServer::start(seed, listen.clone(), ps.clone(), clock.clone())
            .await
            .unwrap();
        addrs.insert(pk(&seed), s.listen_addr().await.unwrap().to_string());
        service.partners.insert(pk(&seed), PartnerState::default());
        partners.push(ps);
        servers.push(s);
    }
    service.users.insert(
        pk(&USER),
        UserAccount {
            salt: SALT.to_vec(),
            quota_bytes: 1 << 30,
            used_bytes: 0,
            root: [0; 32],
        },
    );
    let service = Arc::new(Mutex::new(service));
    let originals: Vec<Vec<u8>> = (1..=4).map(block).collect();
    let put = |b: &Vec<u8>| {
        let mut s = service.lock().unwrap();
        let h = hash_sha256(b);
        s.store.put(Space::UserBlock, &pk(&USER), &h, b).unwrap();
        s.dispersal_queue.push((pk(&USER), h));
    };
    for b in &originals[..3] {
        put(b);
    }

    let dht = DhtNode::start(DhtConfig {
        node_seed: NODE,
        listen: listen.clone(),
        bootstrap: vec![],
        vdf: Arc::new(|_, _| Ok(true)),
        clock: clock.clone(),
    })
    .await
    .unwrap();
    let fabric = NetFabric {
        server: Arc::new(
            BlockServer::start(NODE, listen, service.clone(), clock.clone())
                .await
                .unwrap(),
        ),
        dht: Arc::new(dht),
        service: service.clone(),
        addrs: Arc::new(Mutex::new(addrs)),
        excluded: Default::default(),
    };
    let mut state = DispersalState::default();

    // 3 blocs : un stripe complet, le troisième attend.
    let r = run_cycle(&service, &mut state, &fabric, &cfg, 1_000).await;
    assert_eq!((r.stripes_dispersed, r.published), (1, 1), "{r:?}");
    let u = &state.users[&hex::encode(pk(&USER))];
    assert_eq!((u.stripes.len(), u.pending.len()), (1, 1));
    assert_eq!(u.stripes[0].parity.len(), 4, "coef×k fragments placés");
    // Le Nœud compte les fragments hébergés chez chaque partenaire.
    let hosted: u64 = service
        .lock()
        .unwrap()
        .partners
        .values()
        .map(|p| p.ledger.hosted_for_partner)
        .sum();
    assert_eq!(hosted, 8, "4 de données + 4 de la racine");

    // Délai d'inactivité dépassé : padding.
    let r = run_cycle(&service, &mut state, &fabric, &cfg, 1_200).await;
    assert_eq!((r.stripes_dispersed, r.published), (1, 1), "{r:?}");
    assert!(r.purged > 0, "ancienne racine purgée : {r:?}");
    let u = &state.users[&hex::encode(pk(&USER))];
    assert!(u.stripes[1].padding.contains(&true));

    // Un vrai bloc arrive : le stripe partiel est recréé sans padding.
    put(&originals[3]);
    let r = run_cycle(&service, &mut state, &fabric, &cfg, 1_300).await;
    assert_eq!(r.errors, Vec::<String>::new());
    let u = &state.users[&hex::encode(pk(&USER))];
    assert_eq!(u.stripes.len(), 2);
    assert!(u.stripes.iter().all(|s| !s.padding.contains(&true)));
    assert!(u.pending.is_empty() && !u.dirty);

    // Rien à faire : pas de nouvelle publication.
    let r = run_cycle(&service, &mut state, &fabric, &cfg, 1_301).await;
    assert_eq!((r.stripes_dispersed, r.published), (0, 0));

    // Perte totale du Nœud : DHT + parité des partenaires suffisent.
    let k_attach = derive_k_attach_as_node(&NODE, &pk(&USER), &SALT).unwrap();
    let env = fabric
        .dht
        .get(dispersal_dht_key(&k_attach).to_vec())
        .await
        .unwrap()
        .expect("entrée DispersalManifest publiée");
    let pointer = open_dispersal_entry(&k_attach, &env).unwrap();
    let root_blocks = rebuild(&pointer.root_stripe, &partners, cfg.coef);
    assert_eq!(hash_sha256(&root_blocks[0]), pointer.root_hash);
    let kdc = derive_k_dispersal_content(&k_attach).unwrap();
    let clear = open_index_node(&kdc, &pointer.salt, &CURRENT_HEADER, &root_blocks[0]).unwrap();
    let manifest = decode_manifest(&clear).unwrap();
    assert_eq!(manifest.user_id, pk(&USER));
    assert!(manifest.root.is_leaf);
    let mut recovered: Vec<Vec<u8>> = manifest
        .root
        .entries
        .iter()
        .flat_map(|s| rebuild(s, &partners, cfg.coef))
        .collect();
    recovered.sort();
    let mut want = originals.clone();
    want.sort();
    assert_eq!(recovered, want);
}

/// Minimum de partenaires par stripe : k + 2 par défaut, abaissable pour des
/// essais locaux, jamais sous 1 ni au-dessus de k + 2.
#[test]
fn minimum_confirmations_can_be_lowered_for_local_tests_only_within_bounds() {
    let c = |n| EngineConfig {
        min_confirmations: n,
        ..Default::default()
    };
    assert_eq!(c(0).min_confirmations(), 6);
    assert_eq!(c(2).min_confirmations(), 2);
    assert_eq!(c(99).min_confirmations(), 6);
    let parsed: EngineConfig = serde_json::from_str(r#"{"idle_timeout_s":1,"grace_s":1}"#).unwrap();
    assert_eq!(
        parsed.min_confirmations(),
        6,
        "anciens fichiers : valeur normale"
    );
}

/// Stripe redispersé à l'identique après des confirmations insuffisantes :
/// ses fragments, replacés chez les mêmes partenaires, ne reçoivent pas
/// d'avis d'effacement (sinon le partenaire passerait pour fraudeur).
#[test]
fn identical_redispersal_is_not_tombstoned() {
    use s3m_node::dispersal_engine::{DispersalState, Retired, StripeRec, UserDispersal};
    let r = |h: &str, p: &str| Retired {
        at: 1,
        hash: h.into(),
        partner: p.into(),
    };
    let mut st = DispersalState::default();
    st.users.insert(
        "u".into(),
        UserDispersal {
            stripes: vec![StripeRec {
                parity: vec![(4, "h1".into(), "p1".into())],
                ..Default::default()
            }],
            retired: vec![r("h1", "p1"), r("h1", "p2"), r("h2", "p1")],
            ..Default::default()
        },
    );
    st.drop_referenced_retired();
    assert_eq!(st.users["u"].retired, vec![r("h1", "p2"), r("h2", "p1")]);
}

/// Retrait de la liste noire (dashboard, `s3m-node blacklist-clear`).
#[test]
fn blacklist_entries_can_be_removed() {
    use s3m_node::dispersal_engine::DispersalState;
    let mut st = DispersalState::default();
    for n in ["aa", "bb"] {
        st.upkeep
            .blacklist
            .insert(n.into(), (1, "pos_invalid_response".into()));
        st.partnering.peers.insert(n.into(), Default::default());
    }
    st.users.insert(
        "u".into(),
        UserDispersal {
            stripes: vec![StripeRec {
                parity: vec![(4, "h1".into(), "aa".into()), (5, "h2".into(), "cc".into())],
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    assert!(st.unblacklist("aa"));
    // Fragments effacés lors de la rupture : oubliés, donc replacés et non
    // challengés.
    assert_eq!(
        st.users["u"].stripes[0].parity,
        vec![(5, "h2".to_string(), "cc".to_string())]
    );
    assert!(!st.unblacklist("aa"), "déjà retiré");
    assert!(
        !st.partnering.peers.contains_key("aa"),
        "proposable à nouveau"
    );
    assert!(st.partnering.peers.contains_key("bb"));
    assert_eq!(st.clear_blacklist(), 1);
    assert!(st.upkeep.blacklist.is_empty());
}
