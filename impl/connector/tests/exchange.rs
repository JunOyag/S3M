//! `protocols.echange-blocs` (partie connector) : bout en bout sur TCP
//! local avec un vrai Nœud et un vrai partenaire.

use std::sync::{Arc, Mutex};

use s3m_connector::exchange::*;
use s3m_connector::integrity::BlockSource;
use s3m_connector::write_queue::{Op, Queued, ReplaySink};
use s3m_core::symmetric_suite::hash_sha256;
use s3m_node::exchange::{BlockServer, NodeService, PartnerState, UserAccount};
use s3m_protocol::exchange::*;

const NODE: [u8; 32] = [0x10; 32];
const PARTNER: [u8; 32] = [0x20; 32];
const NEW_NODE: [u8; 32] = [0x30; 32];
const USER: [u8; 32] = [0x40; 32];
const SALT: [u8; 16] = [7; 16];
const NOW: u64 = 1_000_000;

fn pk(s: &[u8; 32]) -> Id {
    ed25519_dalek::SigningKey::from_bytes(s)
        .verifying_key()
        .to_bytes()
}

fn account() -> UserAccount {
    UserAccount {
        salt: SALT.to_vec(),
        quota_bytes: 1 << 20,
        used_bytes: 0,
        root: [0; 32],
    }
}

async fn server(seed: [u8; 32], service: NodeService) -> (BlockServer, libp2p::Multiaddr) {
    let clock: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| NOW);
    let s = BlockServer::start(
        seed,
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        Arc::new(Mutex::new(service)),
        clock,
    )
    .await
    .unwrap();
    let addr = s.listen_addr().await.unwrap();
    (s, addr)
}

#[tokio::test(flavor = "multi_thread")]
async fn connector_writes_reads_then_rescues_from_partner_when_node_is_down() {
    let mut ns = NodeService::new(NODE);
    ns.users.insert(pk(&USER), account());
    let (node, node_addr) = server(NODE, ns).await;
    let mut ps = NodeService::new(PARTNER);
    ps.partners.insert(
        pk(&NODE),
        PartnerState {
            ledger: s3m_node::tombstones::PartnerLedger {
                hosted_for_partner: 10,
                ..Default::default()
            },
            ..Default::default()
        },
    );
    let (_partner, partner_addr) = server(PARTNER, ps).await;

    let client = BlockClient::start().unwrap();
    let session = NodeSession::new(
        client.clone(),
        node_addr,
        &USER,
        &pk(&USER),
        &pk(&NODE),
        &SALT,
    )
    .unwrap();

    // Chemin normal : écriture, lecture, validation de racine avec conflit.
    let block = vec![5u8; 65_536];
    let h = hash_sha256(&block);
    assert_eq!(session.put_block(block.clone()).await.unwrap(), h.to_vec());
    assert_eq!(session.get_block(&h).await.unwrap(), block);
    assert_eq!(
        session.commit_root(&[0; 32], &[1; 32]).await.unwrap(),
        (true, vec![1; 32])
    );
    assert_eq!(
        session.commit_root(&[0; 32], &[2; 32]).await.unwrap(),
        (false, vec![1; 32])
    );
    // Taille du lecteur : quota et occupation communiqués par `RootState`.
    let (quota, used) = session.space().unwrap();
    assert_eq!(quota, 1 << 20);
    assert!(used > 0);
    session.report_incident(&h).await.unwrap();

    // Session usurpée : preuve calculée pour un autre Nœud.
    let wrong = NodeSession::new(
        client.clone(),
        partner_addr.clone(),
        &USER,
        &pk(&USER),
        &pk(&PARTNER),
        &SALT,
    )
    .unwrap();
    assert!(matches!(
        wrong.get_block(&h).await,
        Err(ExchangeError::Refused(Refusal::Unauthorized))
    ));

    // Autorisation de secours, dispersion d'un fragment chez le partenaire.
    let mut keeper = GrantKeeper::new([0x60; 32]);
    assert!(keeper.needs_renewal(NOW));
    keeper.refresh(&session, NOW).await.unwrap();
    assert!(!keeper.needs_renewal(NOW));
    let fragment = vec![9u8; 4096];
    let fh = hash_sha256(&fragment);
    let store = Request {
        credential: None,
        body: Body::StoreFragment {
            data: fragment.clone(),
        },
    };
    let r = node.request(partner_addr.clone(), store).await.unwrap();
    assert!(matches!(r, Response::FragmentReceipt { .. }));

    // Nœud arrêté : lecture de secours chez le partenaire.
    drop(node);
    assert_eq!(
        keeper
            .fetch_fragment(&client, partner_addr.clone(), &fh)
            .await
            .unwrap(),
        fragment
    );
    // Sans autorisation : refus.
    assert!(GrantKeeper::new([0x61; 32])
        .fetch_fragment(&client, partner_addr, &fh)
        .await
        .is_err());
}

/// Perte totale du Nœud : la délégation remise au nouveau Nœud lui ouvre
/// les fragments de l'ancien chez le partenaire.
#[tokio::test(flavor = "multi_thread")]
async fn delegation_reaches_the_new_node_which_reads_old_fragments() {
    let mut ps = NodeService::new(PARTNER);
    ps.partners.insert(
        pk(&NODE),
        PartnerState {
            ledger: s3m_node::tombstones::PartnerLedger {
                hosted_for_partner: 10,
                ..Default::default()
            },
            ..Default::default()
        },
    );
    let fragment = vec![3u8; 100];
    let fh = hash_sha256(&fragment);
    ps.handle(
        b"n",
        Some(pk(&NODE)),
        b"p",
        Request {
            credential: None,
            body: Body::StoreFragment {
                data: fragment.clone(),
            },
        },
        NOW,
    );
    let (_partner, partner_addr) = server(PARTNER, ps).await;

    let mut keeper = GrantKeeper::new([0x60; 32]);
    keeper.grant = Some(issue_grant(&NODE, &keeper.grant_pub(), NOW, &[]));

    let mut nn = NodeService::new(NEW_NODE);
    nn.users.insert(pk(&USER), account());
    let shared = Arc::new(Mutex::new(nn));
    let clock: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| NOW);
    let new_node = BlockServer::start(
        NEW_NODE,
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        shared.clone(),
        clock,
    )
    .await
    .unwrap();
    let new_addr = new_node.listen_addr().await.unwrap();

    let client = BlockClient::start().unwrap();
    let session =
        NodeSession::new(client, new_addr, &USER, &pk(&USER), &pk(&NEW_NODE), &SALT).unwrap();
    let d = keeper.delegate_to(&pk(&NEW_NODE), NOW + 3600).unwrap();
    session.delegate(d).await.unwrap();

    let cred = shared.lock().unwrap().delegations[0].clone();
    let fetch = Request {
        credential: Some(Credential::Delegated(cred)),
        body: Body::FetchFragment { hash: fh.to_vec() },
    };
    assert_eq!(
        new_node.request(partner_addr, fetch).await.unwrap(),
        Response::BlockData(fragment)
    );
}

/// `BlockSource` et `ReplaySink` branchés sur le réseau.
#[tokio::test(flavor = "multi_thread")]
async fn block_source_and_replay_sink_use_the_network() {
    let mut ns = NodeService::new(NODE);
    ns.users.insert(pk(&USER), account());
    let (_node, node_addr) = server(NODE, ns).await;
    let client = BlockClient::start().unwrap();
    let session =
        NodeSession::new(client, node_addr, &USER, &pk(&USER), &pk(&NODE), &SALT).unwrap();
    let block = vec![8u8; 1000];
    let h = hash_sha256(&block);
    let rt = tokio::runtime::Handle::current();

    let stored = block.clone();
    let mut sink = NetReplaySink {
        session: session.clone(),
        runtime: rt.clone(),
        load_block: Box::new(move |x| (*x == h).then(|| stored.clone())),
        build_root: Box::new(|_| Some(([0; 32], [4; 32]))),
    };
    let write = Queued {
        timestamp: 1,
        fs_path: "/a".into(),
        op: Op::WriteBlock { block_hash: h },
    };
    assert!(sink.apply(&write));
    let delete = Queued {
        timestamp: 2,
        fs_path: "/a".into(),
        op: Op::DeleteEntry {
            blocks_to_delete: vec![],
        },
    };
    assert!(sink.apply(&delete), "base [0;32] = racine courante");
    assert!(!sink.apply(&delete), "même base : conflit");

    let source = NetBlockSource {
        session,
        runtime: rt,
        reconstructor: Box::new(|_| None),
    };
    assert_eq!(source.fetch_from_node(&h), Some(block));
    assert_eq!(source.fetch_from_node(&[0xAA; 32]), None);
}

/// Appareil neuf, sans annuaire : le descripteur scellé gardé par le Nœud
/// rend le sel de la racine (`crypto.k-self#k-root`).
#[tokio::test(flavor = "multi_thread")]
async fn a_new_device_recovers_the_root_salt_from_the_node() {
    let mut ns = NodeService::new(NODE);
    ns.users.insert(pk(&USER), account());
    let (_node, node_addr) = server(NODE, ns).await;
    let session = |c: BlockClient| {
        NodeSession::new(c, node_addr.clone(), &USER, &pk(&USER), &pk(&NODE), &SALT).unwrap()
    };
    let old = session(BlockClient::start().unwrap());
    let (root, salt) = ([0x51u8; 32], [0x6cu8; 16]);
    old.note_root(&root, &salt, 1);
    let (ok, _) = old.commit_root(&[0; 32], &root).await.unwrap();
    assert!(ok);

    let new = session(BlockClient::start().unwrap());
    assert_eq!(new.root_from_node(&root), None, "rien lu encore");
    let (_, current) = new.commit_root(&[0; 32], &[0; 32]).await.unwrap();
    assert_eq!(current, root.to_vec());
    assert_eq!(new.root_from_node(&root), Some((salt, 1)));
    assert_eq!(new.root_from_node(&[9; 32]), None);
}
