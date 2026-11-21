//! Invariants de `protocols.espace-secours` (partie connector).

use s3m_connector::emergency::*;
use s3m_connector::write_queue::{Op, Queued, BLOCK_BYTES, DEFAULT_Q_MAX};

const GIB: u64 = 1024 * 1024 * 1024;

fn id(b: u8) -> [u8; 32] {
    let mut v = [0u8; 32];
    v[0] = b;
    v
}

/// Distance XOR à l'identité Utilisateur ; le Nœud hébergeur est exclu.
#[test]
fn partners_are_the_closest_to_the_user_identity_excluding_host() {
    let user = id(0b0000_0000);
    let host = id(0b0000_0001);
    let candidates = [
        id(0b1000_0000),
        host,
        id(0b0000_0010),
        id(0b0000_0100),
        id(0b0100_0000),
        id(0b0000_1000),
    ];
    let p = select_partners(&user, &host, &candidates, 4).unwrap();
    assert_eq!(p, vec![id(2), id(4), id(8), id(0b0100_0000)]);
    assert_eq!(
        select_partners(&user, &host, &candidates[..2], 4),
        Err(EmergencyError::NotEnoughPartners)
    );
}

/// Parts égales, charge maximale Q_max / n_secours par partenaire.
#[test]
fn blocks_are_split_evenly_within_per_partner_cap() {
    let a = assign_blocks(10, 4, DEFAULT_Q_MAX).unwrap();
    let counts: Vec<usize> = (0..4)
        .map(|p| a.iter().filter(|&&x| x == p).count())
        .collect();
    assert_eq!(counts, vec![3, 3, 2, 2]);
    let per = DEFAULT_Q_MAX / 4 / BLOCK_BYTES;
    assert!(assign_blocks((per * 4) as usize, 4, DEFAULT_Q_MAX).is_ok());
    assert_eq!(
        assign_blocks((per * 4 + 1) as usize, 4, DEFAULT_Q_MAX),
        Err(EmergencyError::PartnerOverloaded)
    );
}

fn wb(ts: u64, h: u8) -> Queued {
    Queued {
        timestamp: ts,
        fs_path: "/f".into(),
        op: Op::WriteBlock {
            block_hash: [h; 32],
        },
    }
}

/// Lecture-fusion-écriture : aucun bloc, partenaire ni mutation d'un autre
/// Connecteur n'est perdu ; seq + 1.
#[test]
fn merge_keeps_everything_and_increments_seq() {
    let other = EmergencyState {
        partners: [id(1)].into(),
        blocks: [([1; 32], id(1))].into(),
        mutations: vec![wb(1, 1)],
        base_fs_root_hash: [9; 32],
    };
    let mine = EmergencyState {
        partners: [id(2)].into(),
        blocks: [([2; 32], id(2))].into(),
        mutations: vec![wb(2, 2), wb(1, 1)],
        base_fs_root_hash: [9; 32],
    };
    let (seq, merged) = merge(Some((5, &other)), &mine);
    assert_eq!(seq, 6);
    assert_eq!(merged.partners.len(), 2);
    assert_eq!(merged.blocks.len(), 2);
    assert_eq!(merged.mutations, vec![wb(1, 1), wb(2, 2)]);
    assert_eq!(merge(None, &mine).0, 1);
}

/// Réconciliation idempotente : jamais de mutation référençant un bloc
/// absent, jamais deux fois la même.
#[test]
fn reconciliation_is_idempotent_and_never_references_missing_blocks() {
    let state = EmergencyState {
        mutations: vec![wb(1, 1), wb(2, 2), wb(3, 3)],
        ..Default::default()
    };
    let present = |h: &[u8; 32]| h != &[2u8; 32];
    let first = reconcile(&state, &|_| false, &present);
    assert_eq!(
        first.iter().map(|m| m.timestamp).collect::<Vec<_>>(),
        vec![1, 3]
    );
    let done: Vec<Queued> = first.into_iter().cloned().collect();
    let again = reconcile(&state, &|m| done.contains(m), &present);
    assert!(again.is_empty());
}

/// E_secours = U_backup × Q_max / n_secours : 20 GiO par défaut.
#[test]
fn emergency_capacity_defaults_to_20_gib() {
    assert_eq!(emergency_capacity(20, 4 * GIB, 4), 20 * GIB);
}

// --------------------------------------- bout en bout (TCP local)

use std::sync::{Arc, Mutex};

use s3m_connector::emergency::{
    deposit_block, fetch_block, node_of_peer, peer_of_node, release_blocks, Candidate,
    DepositIdentity,
};
use s3m_connector::exchange::BlockClient;
use s3m_node::exchange::{BlockServer, NodeService};
use s3m_protocol::emergency::{emergency_keys, Partner};

const PARTNER: [u8; 32] = [0x20; 32];

fn pk(s: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(s)
        .verifying_key()
        .to_bytes()
}

/// `protocols.espace-secours` : dépôt authentifié par l'identité VDF,
/// relecture par la clé de secours (Nœud de retour), libération signée.
#[tokio::test(flavor = "multi_thread")]
async fn deposit_fetch_and_release_against_a_real_partner() {
    let mut ps = NodeService::new(PARTNER);
    ps.vdf = Some(Arc::new(|_, _| true));
    let clock: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| 1_000_000);
    let server = BlockServer::start(
        PARTNER,
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        Arc::new(Mutex::new(ps)),
        clock,
    )
    .await
    .unwrap();
    let addr = server.listen_addr().await.unwrap();
    assert_eq!(peer_of_node(&pk(&PARTNER)), Some(server.peer_id()));
    assert_eq!(node_of_peer(&server.peer_id()), Some(pk(&PARTNER)));

    let sig_priv_user = [3; 32];
    let id = DepositIdentity {
        sig_priv_user,
        sig_pub_user: pk(&sig_priv_user),
        proof: s3m_core::vdf::VdfProof {
            y: vec![1],
            pi: vec![2],
        },
        keys: emergency_keys(&[9; 32]).unwrap(),
    };
    let c = Candidate {
        partner: Partner {
            node_id: pk(&PARTNER),
            ip: "127.0.0.1".into(),
            port: 0,
        },
        addr: addr.clone(),
    };
    let client = BlockClient::start().unwrap();
    let data = vec![5u8; 65_536];
    let hash = s3m_core::symmetric_suite::hash_sha256(&data);
    deposit_block(&client, &c, &id, data.clone()).await.unwrap();

    // Le Nœud de retour (autre client) relit par la clé de secours.
    let other = BlockClient::start().unwrap();
    assert_eq!(
        fetch_block(&other, addr.clone(), &id.keys.sig_pub, &hash).await,
        Some(data)
    );
    assert_eq!(
        fetch_block(&other, addr.clone(), &[1; 32], &hash).await,
        None
    );

    let mut ts = 10;
    assert_eq!(
        release_blocks(&other, addr.clone(), &id.keys, &mut ts, &[hash])
            .await
            .unwrap(),
        1
    );
    assert_eq!(ts, 11);
    assert_eq!(
        fetch_block(&other, addr, &id.keys.sig_pub, &hash).await,
        None
    );
}
