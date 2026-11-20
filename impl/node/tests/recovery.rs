//! Snapshot du NodeManifest et restauration du Nœud depuis sa seule seed
//! (`deploiement.disaster-recovery`) : quatre partenaires réels et un pair
//! DHT d'amorçage sur TCP local ; le Nœud d'origine disparaît.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use p2p_storage_core::symmetric_suite::hash_sha256;
use p2p_storage_core::vdf::VdfProof;
use p2p_storage_node::chunk_store::Space;
use p2p_storage_node::dht_directory::{DhtConfig, DhtNode};
use p2p_storage_node::dispersal_engine::*;
use p2p_storage_node::exchange::{BlockServer, NodeService, PartnerState, UserAccount};
use p2p_storage_node::publish::{publish_if_due, NodeEntryState};
use p2p_storage_node::recovery::recover;
use p2p_storage_node::snapshot_engine::run_snapshot;

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

type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

async fn dht(seed: [u8; 32], bootstrap: Vec<libp2p::Multiaddr>, clock: &Clock) -> DhtNode {
    DhtNode::start(DhtConfig {
        node_seed: seed,
        listen: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        bootstrap,
        vdf: Arc::new(|_, _| Ok(true)),
        clock: clock.clone(),
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn node_restored_from_seed_alone_recovers_users_partners_and_every_block() {
    let cfg = EngineConfig {
        k: 2,
        coef: 2,
        idle_timeout_s: 100,
        grace_s: 0,
    };
    let clock: Clock = Arc::new(|| 1_000);
    let listen: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    let boot = dht([0x99; 32], vec![], &clock).await;
    let boot_addr = boot.listen_addr().await.unwrap();

    let mut partner_servers = Vec::new();
    let mut addrs = HashMap::new();
    let mut service = NodeService::new(NODE);
    for i in 0..4u8 {
        let seed = [0x60 + i; 32];
        let mut ps = NodeService::new(seed);
        ps.partners.insert(
            pk(&NODE),
            PartnerState {
                allowance: 1_000,
                ..Default::default()
            },
        );
        let s = BlockServer::start(
            seed,
            listen.clone(),
            Arc::new(Mutex::new(ps)),
            clock.clone(),
        )
        .await
        .unwrap();
        addrs.insert(pk(&seed), s.listen_addr().await.unwrap().to_string());
        service.partners.insert(
            pk(&seed),
            PartnerState {
                allowance: 500 + i as u64,
                ..Default::default()
            },
        );
        partner_servers.push(s);
    }
    service.users.insert(
        pk(&USER),
        UserAccount {
            salt: vec![7; 16],
            quota_bytes: 1 << 30,
            used_bytes: 0,
            root: [5; 32],
        },
    );
    let service = Arc::new(Mutex::new(service));
    let originals = [block(1), block(2), block(3)];
    for b in &originals {
        let mut s = service.lock().unwrap();
        let h = hash_sha256(b);
        s.store.put(Space::UserBlock, &pk(&USER), &h, b).unwrap();
        s.dispersal_queue.push((pk(&USER), h));
    }

    // Nœud d'origine : dispersion, snapshot, entrée Node publiée.
    {
        let fabric = NetFabric {
            server: Arc::new(
                BlockServer::start(NODE, listen.clone(), service.clone(), clock.clone())
                    .await
                    .unwrap(),
            ),
            dht: Arc::new(dht(NODE, vec![boot_addr.clone()], &clock).await),
            service: service.clone(),
            addrs: Arc::new(Mutex::new(addrs.clone())),
        };
        let mut state = DispersalState::default();
        run_cycle(&service, &mut state, &fabric, &cfg, 1_000).await;
        let r = run_cycle(&service, &mut state, &fabric, &cfg, 1_200).await;
        assert!(r.errors.is_empty(), "{r:?}");
        assert!(
            run_snapshot(&service, &mut state, &fabric, &cfg, 1_200).await,
            "{:?}",
            state.snapshot.last_error
        );
        assert!(
            !run_snapshot(&service, &mut state, &fabric, &cfg, 1_201).await,
            "inchangé"
        );
        let pointer = hex::decode(state.snapshot.pointer.as_ref().unwrap()).unwrap();
        let entry = Mutex::new(NodeEntryState::default());
        let proof = VdfProof {
            y: vec![1; 100],
            pi: vec![2; 100],
        };
        publish_if_due(
            &fabric.dht,
            &NODE,
            &pk(&NODE),
            &[0; 32],
            ("127.0.0.1".into(), 1),
            &proof,
            Some(pointer),
            &entry,
            1_200,
        )
        .await;
        assert!(
            entry.lock().unwrap().published_snapshot.is_some(),
            "{:?}",
            entry.lock().unwrap().last_error
        );
        assert!(
            boot.get(pk(&NODE).to_vec()).await.unwrap().is_some(),
            "répliquée sur le pair d'amorçage"
        );
    }
    drop(service);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Nouvelle installation : seule la seed.
    let fresh = Arc::new(Mutex::new(NodeService::new(NODE)));
    let server = BlockServer::start(NODE, listen, fresh.clone(), clock.clone())
        .await
        .unwrap();
    let dht2 = dht(NODE, vec![boot_addr], &clock).await;
    let mut state = DispersalState::default();
    let found = Mutex::new(HashMap::new());
    let r = recover(&fresh, &mut state, &server, &dht2, &cfg, &found, 2_000)
        .await
        .unwrap();
    assert_eq!((r.users, r.partners, r.blocks), (1, 4, 3), "{r:?}");
    assert!(r.errors.is_empty(), "{r:?}");

    let s = fresh.lock().unwrap();
    for b in &originals {
        let (o, d) = s.store.get(Space::UserBlock, &hash_sha256(b)).unwrap();
        assert_eq!((o, &d), (pk(&USER), b));
    }
    assert_eq!(s.users[&pk(&USER)].salt, vec![7; 16]);
    assert_eq!(s.users[&pk(&USER)].used_bytes, 3 * 65_536);
    assert!(s.adopt_next_root.contains(&pk(&USER)));
    let allowances: Vec<u64> = (0..4u8)
        .map(|i| s.partners[&pk(&[0x60 + i; 32])].allowance)
        .collect();
    assert_eq!(allowances, vec![500, 501, 502, 503]);
    assert!(
        s.partners
            .values()
            .map(|p| p.ledger.hosted_for_partner)
            .sum::<u64>()
            > 0
    );
    // Chaque partenaire qui héberge un fragment a une adresse (table du
    // catalogue, ou son entrée DHT Node en production).
    let found = found.lock().unwrap();
    for (id, p) in &s.partners {
        if p.ledger.hosted_for_partner > 0 {
            assert!(found.contains_key(id), "adresse de {}", hex::encode(id));
        }
    }
    drop(found);
    let u = &state.users[&hex::encode(pk(&USER))];
    assert_eq!(u.stripes.len(), 2);
    assert!(u.pointer.is_some() && !u.index.is_empty());
    assert!(state.snapshot.pointer.is_some());
}
