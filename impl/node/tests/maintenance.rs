//! Perte d'un volume : maintenance automatique
//! (`securite.integrite-autoreparation#maintenance`) — un Nœud sur disque
//! réel et six partenaires sur TCP local.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use s3m_core::symmetric_suite::hash_sha256;
use s3m_node::chunk_store::Space;
use s3m_node::dht_directory::{DhtConfig, DhtNode};
use s3m_node::dispersal_engine::*;
use s3m_node::exchange::{BlockServer, NodeService, PartnerState, UserAccount};
use s3m_node::upkeep::*;
use s3m_node::{PhysicalStore, VolumeConfig};

const NODE: [u8; 32] = [0x11; 32];
const USER: [u8; 32] = [0x41; 32];

struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

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

const CFG: EngineConfig = EngineConfig {
    k: 2,
    coef: 2,
    idle_timeout_s: 100,
    grace_s: 0,
    min_confirmations: 0,
};
const UCFG: UpkeepConfig = UpkeepConfig {
    challenges_per_cycle: 64,
    analysis_period_s: 100,
    available_window_s: 150,
    scrub_period_s: 86_400,
};

struct Net {
    service: Arc<Mutex<NodeService>>,
    partners: HashMap<[u8; 32], Arc<Mutex<NodeService>>>,
    fabric: NetFabric,
    _servers: Vec<BlockServer>,
}

async fn network(service: NodeService) -> Net {
    let clock: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| 1_000);
    let listen: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    let mut service = service;
    service.partner_policy.filler = false;
    let mut partners = HashMap::new();
    let mut servers = Vec::new();
    let mut addrs = HashMap::new();
    for i in 0..6u8 {
        let seed = [0x70 + i; 32];
        let mut ps = NodeService::new(seed);
        ps.partner_policy.filler = false;
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
    Net {
        service,
        partners,
        fabric,
        _servers: servers,
    }
}

/// Dossier du volume supprimé : maintenance, blocs reconstruits depuis la
/// parité des partenaires, Utilisateurs prévenus, sortie de maintenance.
#[tokio::test(flavor = "multi_thread")]
async fn a_deleted_volume_is_rebuilt_from_the_network() {
    let dir = std::env::temp_dir().join(format!("p2p-maint-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let _t = Temp(dir.clone());
    let phys = PhysicalStore::open(
        dir.join("node.sqlite"),
        vec![VolumeConfig {
            volume_id: 0,
            mount_path: dir.join("vol0"),
            max_capacity_bytes: 64 * 1024 * 1024,
        }],
    )
    .unwrap();
    let mut ns = NodeService::new(NODE);
    ns.store = Box::new(phys);
    let net = network(ns).await;
    let originals = [block(1), block(2)];
    let foreign = pk(&[0x70; 32]);
    {
        let mut s = net.service.lock().unwrap();
        for b in &originals {
            let h = hash_sha256(b);
            s.store.put(Space::UserBlock, &pk(&USER), &h, b).unwrap();
            s.dispersal_queue.push((pk(&USER), h));
        }
        // Fragment gardé pour un partenaire, perdu lui aussi.
        let f = block(9);
        s.store.put(Space::Fragment, &foreign, &hash_sha256(&f), &f).unwrap();
        s.partners.get_mut(&foreign).unwrap().ledger.hosted_by_partner = 1;
    }
    let mut state = DispersalState::default();
    let r = run_cycle(&net.service, &mut state, &net.fabric, &CFG, 1_000).await;
    assert_eq!(r.stripes_dispersed, 1, "{r:?}");
    let r = run_upkeep(&net.service, &mut state, &net.fabric, &CFG, &UCFG, 1_000).await;
    assert_eq!(r.local_repaired, 0);
    assert!(state.upkeep.maintenance.is_none());

    std::fs::remove_dir_all(dir.join("vol0")).unwrap();
    let r = run_upkeep(&net.service, &mut state, &net.fabric, &CFG, &UCFG, 2_000).await;
    assert_eq!(r.local_repaired, 2, "{r:?}");
    let m = state.upkeep.last_maintenance.clone().expect("maintenance terminée");
    assert_eq!(
        (m.lost_user_blocks, m.lost_fragments, m.repaired, m.irrecoverable),
        (2, 1, 2, 0)
    );
    assert!(state.upkeep.maintenance.is_none());
    let s = net.service.lock().unwrap();
    assert!(!s.maintenance);
    for b in &originals {
        let (o, got) = s.store.get(Space::UserBlock, &hash_sha256(b)).unwrap();
        assert_eq!((o, &got), (pk(&USER), b));
    }
    assert_eq!(s.partners[&foreign].ledger.hosted_by_partner, 0);
    assert!(dir.join("vol0").exists());
    // Utilisateurs prévenus : début et fin de maintenance.
    assert_eq!(s.channel.outbox.sent.len(), 2);
}

/// Partenaire en maintenance : il refuse les dépôts et signale ses
/// fragments perdus ; le fragment est replacé sans manquement.
#[tokio::test(flavor = "multi_thread")]
async fn a_partner_in_maintenance_is_not_penalised() {
    let net = network(NodeService::new(NODE)).await;
    let b = [block(3), block(4)];
    {
        let mut s = net.service.lock().unwrap();
        for x in &b {
            let h = hash_sha256(x);
            s.store.put(Space::UserBlock, &pk(&USER), &h, x).unwrap();
            s.dispersal_queue.push((pk(&USER), h));
        }
    }
    let mut state = DispersalState::default();
    run_cycle(&net.service, &mut state, &net.fabric, &CFG, 1_000).await;
    let user = hex::encode(pk(&USER));
    let (_, frag, holder) = state.users[&user].stripes[0].parity[0].clone();
    let holder: [u8; 32] = hex::decode(&holder).unwrap().try_into().unwrap();
    let frag: [u8; 32] = hex::decode(&frag).unwrap().try_into().unwrap();
    {
        let mut p = net.partners[&holder].lock().unwrap();
        p.maintenance = true;
        p.store.remove(Space::Fragment, &pk(&NODE), &frag);
    }
    let r = run_upkeep(&net.service, &mut state, &net.fabric, &CFG, &UCFG, 1_000).await;
    assert_eq!(r.lost, 1, "{r:?}");
    let s = net.service.lock().unwrap();
    assert_eq!(s.partners[&holder].failures, 0);
    drop(s);
    // Le fragment a été replacé ailleurs.
    let now_holder = &state.users[&user].stripes[0].parity[0].2;
    assert_ne!(*now_holder, hex::encode(holder));
}
