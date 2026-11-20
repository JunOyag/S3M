//! Contrôles et réparation automatiques (`securite.pos-challenges`,
//! `securite.blacklist-fraude`, `protocols.volatilite-reparation`,
//! `securite.integrite-autoreparation`) : un Nœud et six partenaires réels
//! sur TCP local — fraude, absence, corruption locale.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use p2p_storage_core::symmetric_suite::hash_sha256;
use p2p_storage_node::chunk_store::Space;
use p2p_storage_node::dht_directory::{DhtConfig, DhtNode};
use p2p_storage_node::dispersal_engine::*;
use p2p_storage_node::exchange::{BlockServer, NodeService, PartnerState, UserAccount};
use p2p_storage_node::upkeep::*;

const NODE: [u8; 32] = [0x10; 32];
const USER: [u8; 32] = [0x40; 32];

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

#[tokio::test(flavor = "multi_thread")]
async fn fraud_absence_and_local_corruption_are_repaired_automatically() {
    let cfg = EngineConfig {
        k: 2,
        coef: 2,
        idle_timeout_s: 100,
        grace_s: 0,
    };
    let ucfg = UpkeepConfig {
        challenges_per_cycle: 64,
        analysis_period_s: 100,
        available_window_s: 150,
        scrub_period_s: 100,
    };
    let clock: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| 1_000);
    let listen: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();

    let mut partners: HashMap<[u8; 32], Arc<Mutex<NodeService>>> = HashMap::new();
    let mut servers: HashMap<[u8; 32], BlockServer> = HashMap::new();
    let mut addrs = HashMap::new();
    let mut service = NodeService::new(NODE);
    for i in 0..6u8 {
        let seed = [0x60 + i; 32];
        let mut ps = NodeService::new(seed);
        ps.partners.insert(
            pk(&NODE),
            PartnerState {
                allowance: 1_000,
                ..Default::default()
            },
        );
        let ps = Arc::new(Mutex::new(ps));
        let s = BlockServer::start(seed, listen.clone(), ps.clone(), clock.clone())
            .await
            .unwrap();
        addrs.insert(pk(&seed), s.listen_addr().await.unwrap().to_string());
        service.partners.insert(pk(&seed), PartnerState::default());
        partners.insert(pk(&seed), ps);
        servers.insert(pk(&seed), s);
    }
    service.users.insert(
        pk(&USER),
        UserAccount {
            salt: vec![7; 16],
            quota_bytes: 1 << 30,
            used_bytes: 0,
            root: [0; 32],
        },
    );
    let service = Arc::new(Mutex::new(service));
    let originals = [block(1), block(2)];
    for b in &originals {
        let mut s = service.lock().unwrap();
        let h = hash_sha256(b);
        s.store.put(Space::UserBlock, &pk(&USER), &h, b).unwrap();
        s.dispersal_queue.push((pk(&USER), h));
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
            BlockServer::start(NODE, listen, service.clone(), clock)
                .await
                .unwrap(),
        ),
        dht: Arc::new(dht),
        service: service.clone(),
        addrs: Arc::new(Mutex::new(addrs)),
        excluded: Default::default(),
    };
    let mut state = DispersalState::default();
    let user = hex::encode(pk(&USER));
    let holder = |st: &DispersalState, i: usize| -> [u8; 32] {
        hex::decode(&st.users[&user].stripes[0].parity[i].2)
            .unwrap()
            .try_into()
            .unwrap()
    };

    let r = run_cycle(&service, &mut state, &fabric, &cfg, 1_000).await;
    assert_eq!((r.stripes_dispersed, r.published), (1, 1), "{r:?}");

    // Tout va bien : les quatre fragments répondent.
    let r = run_upkeep(&service, &mut state, &fabric, &cfg, &ucfg, 1_000).await;
    assert_eq!((r.challenged, r.passed, r.repaired), (4, 4, 0), "{r:?}");

    // Fraude : un partenaire altère le fragment qu'il héberge.
    let cheater = holder(&state, 0);
    let frag_hash: [u8; 32] = hex::decode(&state.users[&user].stripes[0].parity[0].1)
        .unwrap()
        .try_into()
        .unwrap();
    partners[&cheater]
        .lock()
        .unwrap()
        .store
        .replace(Space::Fragment, &pk(&NODE), &frag_hash, &[0xEE; 65_536])
        .unwrap();
    let r = run_upkeep(&service, &mut state, &fabric, &cfg, &ucfg, 1_050).await;
    assert_eq!(r.frauds, vec![cheater], "{r:?}");
    assert!(r.repaired >= 1);
    assert!(state.upkeep.is_blacklisted(&cheater));
    assert!(!service.lock().unwrap().partners.contains_key(&cheater));
    let parity = &state.users[&user].stripes[0].parity;
    assert_eq!(parity.len(), 4);
    assert!(parity.iter().all(|(_, _, p)| *p != hex::encode(cheater)));
    assert!(state.users[&user].dirty, "arbre d'index à réémettre");
    let r = run_cycle(&service, &mut state, &fabric, &cfg, 1_050).await;
    assert_eq!(r.published, 1, "{r:?}");

    // Absence : un hébergeur s'arrête ; au-delà de la fenêtre, son fragment
    // est replacé chez le dernier partenaire libre.
    let absent = holder(&state, 1);
    drop(servers.remove(&absent));
    let r = run_upkeep(&service, &mut state, &fabric, &cfg, &ucfg, 1_300).await;
    assert!(r.timeouts >= 1, "{r:?}");
    assert!(r.frauds.is_empty(), "absence ≠ fraude : {r:?}");
    let parity = &state.users[&user].stripes[0].parity;
    assert_eq!(parity.len(), 4);
    assert!(parity.iter().all(|(_, _, p)| *p != hex::encode(absent)));
    assert!(
        state.users[&user]
            .retired
            .iter()
            .any(|x| x.partner == hex::encode(absent)),
        "ancien fragment à purger quand l'absent reviendra"
    );

    // Corruption de la copie locale : reconstruite depuis la parité.
    let h = hash_sha256(&originals[0]);
    service
        .lock()
        .unwrap()
        .store
        .replace(Space::UserBlock, &pk(&USER), &h, &[0u8; 65_536])
        .unwrap();
    let r = run_upkeep(&service, &mut state, &fabric, &cfg, &ucfg, 1_400).await;
    assert_eq!(r.local_repaired, 1, "{r:?}");
    let healed = service
        .lock()
        .unwrap()
        .store
        .get(Space::UserBlock, &h)
        .unwrap()
        .1;
    assert_eq!(healed, originals[0]);
    assert!(state
        .upkeep
        .events
        .iter()
        .any(|e| e.contains("liste noire")));
}
