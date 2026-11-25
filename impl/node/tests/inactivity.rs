//! Durée d'inactivité des Utilisateurs
//! (`protocols.partenariat-automatique#inactivite`).

use std::sync::Mutex;

use s3m_core::symmetric_suite::hash_sha256;
use s3m_node::chunk_store::Space;
use s3m_node::dispersal_engine::{DispersalState, StripeRec, UserDispersal};
use s3m_node::exchange::{NodeService, UserAccount};
use s3m_node::inactivity::*;

const NOW: u64 = 2_000_000_000;
const AUTO: [u8; 32] = [1; 32];
const MANUAL: [u8; 32] = [2; 32];

fn account() -> UserAccount {
    UserAccount {
        salt: vec![7; 16],
        quota_bytes: 1 << 30,
        used_bytes: 0,
        root: [0; 32],
    }
}

fn service() -> NodeService {
    let mut s = NodeService::new([9; 32]);
    s.users.insert(AUTO, account());
    s.users.insert(MANUAL, account());
    s.auto_attached.insert(AUTO);
    s
}

#[test]
fn zero_means_eternal_and_the_minimum_is_180_days() {
    assert_eq!(validate_days(0), Ok(0));
    assert_eq!(validate_days(180), Ok(180));
    assert_eq!(validate_days(100_000), Ok(100_000));
    assert!(validate_days(179).is_err());
    assert!(validate_days(1).is_err());
}

#[test]
fn auto_attached_users_follow_the_policy_and_manual_ones_are_eternal() {
    let mut s = service();
    assert_eq!(s.attach_policy.inactivity_days, 180);
    s.last_active.insert(AUTO, NOW - 10 * DAY_S);
    assert_eq!(remaining_days(&s, &AUTO, NOW), Some(170));
    assert_eq!(remaining_days(&s, &MANUAL, NOW), None);
    // Valeur propre : éternel, ou plus longue ; aussi pour un rattachement manuel.
    s.inactivity_days.insert(AUTO, 0);
    assert_eq!(remaining_days(&s, &AUTO, NOW), None);
    s.inactivity_days.insert(MANUAL, 365);
    s.last_active.insert(MANUAL, NOW - DAY_S / 2);
    assert_eq!(remaining_days(&s, &MANUAL, NOW), Some(365));
}

#[test]
fn a_stopped_node_gives_its_downtime_back() {
    let mut s = service();
    s.last_active.insert(AUTO, NOW - 200 * DAY_S);
    // Arrêté 100 jours après la dernière activité, pendant 100 jours.
    credit_downtime(&mut s, NOW - 100 * DAY_S, NOW);
    assert_eq!(remaining_days(&s, &AUTO, NOW), Some(80));
}

#[test]
fn an_expired_user_is_deleted_with_its_blocks_and_fragments() {
    let mut s = service();
    let b = vec![3u8; 65_536];
    let h = hash_sha256(&b);
    s.store.put(Space::UserBlock, &AUTO, &h, &b).unwrap();
    s.root_seals.insert(AUTO, vec![1; 47]);
    s.last_active.insert(AUTO, NOW - 180 * DAY_S);
    s.last_active.insert(MANUAL, NOW - 1_000 * DAY_S);
    let service = Mutex::new(s);
    let mut state = DispersalState::default();
    state.users.insert(
        hex::encode(AUTO),
        UserDispersal {
            stripes: vec![StripeRec {
                id: "s".into(),
                data: vec![hex::encode(h)],
                padding: vec![false],
                parity: vec![(1, hex::encode([5; 32]), hex::encode([6; 32]))],
                salt: None,
            }],
            ..Default::default()
        },
    );

    assert_eq!(purge_expired(&service, &mut state, NOW), vec![AUTO]);
    let s = service.lock().unwrap();
    assert!(!s.users.contains_key(&AUTO));
    assert!(s.users.contains_key(&MANUAL), "rattachement manuel : éternel");
    assert!(s.store.get(Space::UserBlock, &h).is_none());
    assert!(s.root_seals.is_empty());
    drop(s);
    // Fragment libéré chez le partenaire par les avis de suppression.
    let rest = &state.users[&hex::encode(AUTO)];
    assert!(rest.stripes.is_empty() && rest.pointer.is_none());
    assert_eq!(rest.retired.len(), 1);
    // Une fois libéré, plus rien ne reste.
    state.users.get_mut(&hex::encode(AUTO)).unwrap().retired.clear();
    assert!(purge_expired(&service, &mut state, NOW).is_empty());
    assert!(!state.users.contains_key(&hex::encode(AUTO)));
}
