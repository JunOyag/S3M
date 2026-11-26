//! Contrôles et réparation automatiques (`securite.pos-challenges`,
//! `securite.blacklist-fraude`, `protocols.volatilite-reparation`,
//! `securite.integrite-autoreparation`) : un Nœud et six partenaires réels
//! sur TCP local — fraude, absence, corruption locale.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use s3m_core::symmetric_suite::hash_sha256;
use s3m_node::chunk_store::Space;
use s3m_node::dht_directory::{DhtConfig, DhtNode};
use s3m_node::dispersal_engine::*;
use s3m_node::exchange::{BlockServer, NodeService, PartnerState, UserAccount};
use s3m_node::upkeep::*;

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
        min_confirmations: 0,
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
    service.partner_policy.filler = false;
    for i in 0..7u8 {
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

    // Perte : un partenaire n'a plus le fragment (disque, effacement) —
    // replacé ailleurs, échec compté, sans liste noire ni rupture.
    let loser = holder(&state, 1);
    let lost_hash: [u8; 32] = hex::decode(&state.users[&user].stripes[0].parity[1].1)
        .unwrap()
        .try_into()
        .unwrap();
    assert!(partners[&loser]
        .lock()
        .unwrap()
        .store
        .remove(Space::Fragment, &pk(&NODE), &lost_hash));
    let r = run_upkeep(&service, &mut state, &fabric, &cfg, &ucfg, 1_060).await;
    assert!(r.frauds.is_empty(), "perte ≠ fraude : {r:?}");
    assert_eq!(r.lost, 1, "{r:?}");
    assert!(r.repaired >= 1, "{r:?}");
    assert!(!state.upkeep.is_blacklisted(&loser));
    assert!(service.lock().unwrap().partners.contains_key(&loser));
    assert_eq!(state.upkeep.pos_fail.get(&hex::encode(loser)), Some(&1));
    let parity = &state.users[&user].stripes[0].parity;
    assert_eq!(parity.len(), 4);
    assert!(parity.iter().all(|(_, _, p)| *p != hex::encode(loser)));
    let r = run_cycle(&service, &mut state, &fabric, &cfg, 1_060).await;
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

/// Fragments non placés faute de partenaires : complétés au cycle suivant
/// l'arrivée de nouveaux partenaires, sans attendre l'analyse quotidienne.
#[tokio::test(flavor = "multi_thread")]
async fn unplaced_fragments_are_completed_at_the_next_cycle() {
    let cfg = EngineConfig {
        k: 2,
        coef: 2,
        idle_timeout_s: 100,
        grace_s: 0,
        min_confirmations: 1,
    };
    let ucfg = UpkeepConfig {
        challenges_per_cycle: 0,
        ..Default::default()
    };
    let clock: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| 1_000);
    let listen: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    let mut servers = Vec::new();
    let mut addrs = HashMap::new();
    let mut later = Vec::new();
    let mut service = NodeService::new(NODE);
    service.partner_policy.filler = false;
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
        let s = BlockServer::start(seed, listen.clone(), ps, clock.clone())
            .await
            .unwrap();
        addrs.insert(pk(&seed), s.listen_addr().await.unwrap().to_string());
        if i < 2 {
            service.partners.insert(pk(&seed), PartnerState::default());
        } else {
            later.push(pk(&seed));
        }
        servers.push(s);
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
    for b in [block(1), block(2)] {
        let mut s = service.lock().unwrap();
        let h = hash_sha256(&b);
        s.store.put(Space::UserBlock, &pk(&USER), &h, &b).unwrap();
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
    let r = run_cycle(&service, &mut state, &fabric, &cfg, 1_000).await;
    assert_eq!(r.stripes_dispersed, 1, "{r:?}");
    assert_eq!(state.users[&user].stripes[0].parity.len(), 2);
    // Sans partenaire libre : rien n'est tenté.
    let r = run_upkeep(&service, &mut state, &fabric, &cfg, &ucfg, 1_010).await;
    assert_eq!(r.repaired, 0, "{r:?}");
    for p in later {
        service.lock().unwrap().partners.insert(p, PartnerState::default());
    }
    let r = run_upkeep(&service, &mut state, &fabric, &cfg, &ucfg, 1_040).await;
    assert_eq!(r.repaired, 2, "{r:?}");
    let s = &state.users[&user].stripes[0];
    let mut holders: Vec<_> = s.parity.iter().map(|(_, _, p)| p.clone()).collect();
    holders.sort();
    holders.dedup();
    assert_eq!((s.parity.len(), holders.len()), (4, 4));
}

/// Remplissage de l'espace promis (`node.PartnerAccount#remplissage`) :
/// déposé jusqu'au quota, contrôlé, libéré quand la place manque, et un
/// fragment de remplissage perdu est un manquement.
#[tokio::test(flavor = "multi_thread")]
async fn filler_fills_the_quota_is_checked_and_released_on_demand() {
    let cfg = EngineConfig {
        k: 2,
        coef: 2,
        idle_timeout_s: 100,
        grace_s: 0,
        min_confirmations: 1,
    };
    let ucfg = UpkeepConfig {
        challenges_per_cycle: 8,
        ..Default::default()
    };
    let clock: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| 1_000);
    let listen: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    let mut servers = Vec::new();
    let mut addrs = HashMap::new();
    let mut hosts = Vec::new();
    let mut service = NodeService::new(NODE);
    service.partner_policy.trust_initial_blocks = 4;
    for i in 0..2u8 {
        let seed = [0x70 + i; 32];
        let mut ps = NodeService::new(seed);
        ps.partners.insert(pk(&NODE), PartnerState::default());
        let ps = Arc::new(Mutex::new(ps));
        let s = BlockServer::start(seed, listen.clone(), ps.clone(), clock.clone())
            .await
            .unwrap();
        addrs.insert(pk(&seed), s.listen_addr().await.unwrap().to_string());
        service.partners.insert(pk(&seed), PartnerState::default());
        hosts.push((pk(&seed), ps));
        servers.push(s);
    }
    let service = Arc::new(Mutex::new(service));
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
    let (p0, p1) = (hosts[0].0, hosts[1].0);
    let held = |p: &[u8; 32]| service.lock().unwrap().partners[p].ledger.hosted_for_partner;

    run_upkeep(&service, &mut state, &fabric, &cfg, &ucfg, 1_000).await;
    assert_eq!((held(&p0), held(&p1)), (4, 4));
    assert_eq!(state.upkeep.fillers[&hex::encode(p0)].len(), 4);
    // Quota atteint : rien de plus ; contrôles réussis.
    let r = run_upkeep(&service, &mut state, &fabric, &cfg, &ucfg, 1_030).await;
    assert_eq!((held(&p0), held(&p1)), (4, 4));
    assert!(r.passed >= 2, "{r:?}");
    assert!(service.lock().unwrap().partners[&p0].proved_at >= 1_000);
    // Place demandée chez p0 : remplissage libéré, pas de nouveau dépôt.
    service.lock().unwrap().need_room.insert(p0);
    run_upkeep(&service, &mut state, &fabric, &cfg, &ucfg, 1_060).await;
    assert_eq!(held(&p0), 0);
    assert_eq!(
        hosts[0].1.lock().unwrap().partners[&pk(&NODE)].ledger.hosted_by_partner,
        0
    );
    // Remplissage perdu chez p1 : manquement au contrôle.
    {
        let mut h = hosts[1].1.lock().unwrap();
        for (_, hash) in &state.upkeep.fillers[&hex::encode(p1)] {
            let hash: [u8; 32] = hex::decode(hash).unwrap().try_into().unwrap();
            h.store.remove(Space::Fragment, &pk(&NODE), &hash);
        }
    }
    let mut t = 1_090;
    while service.lock().unwrap().partners[&p1].failures == 0 && t < 1_400 {
        run_upkeep(&service, &mut state, &fabric, &cfg, &ucfg, t).await;
        t += 30;
    }
    assert!(service.lock().unwrap().partners[&p1].failures >= 1);
    assert!(service.lock().unwrap().suspended(t).contains(&p1));
    // Après une restauration, le Nœud ignore le remplissage que p0 garde
    // déjà : le refus faute de place n'est pas un manquement.
    run_upkeep(&service, &mut state, &fabric, &cfg, &ucfg, t).await;
    assert_eq!(held(&p0), 4);
    service.lock().unwrap().partners.get_mut(&p0).unwrap().ledger.hosted_for_partner = 0;
    state.upkeep.fillers.remove(&hex::encode(p0));
    run_upkeep(&service, &mut state, &fabric, &cfg, &ucfg, t + 30).await;
    assert_eq!(service.lock().unwrap().partners[&p0].failures, 0, "pas de manquement");
    assert_eq!(held(&p0), 4, "compté plein");
}

/// Partenaires mis en retrait à tort : réhabilités, manquements effacés.
#[test]
fn retired_partners_can_be_rehabilitated() {
    let p = pk(&[0x55; 32]);
    let mut service = NodeService::new(NODE);
    service.partners.insert(p, PartnerState { failures: 9, suspended_until: 99, ..Default::default() });
    let service = Mutex::new(service);
    let mut state = DispersalState::default();
    let name = hex::encode(p);
    state.partnering.peers.insert(name.clone(), s3m_node::partnering::Peer { status: "retrait".into(), ..Default::default() });
    state.upkeep.retiring.insert(name.clone());
    assert_eq!(s3m_node::partnering::rehabilitate(&mut state, &service), 1);
    assert_eq!(state.partnering.peers[&name].status, "partenaire");
    assert!(!state.upkeep.retiring.contains(&name));
    assert_eq!(service.lock().unwrap().partners[&p].failures, 0);
}
