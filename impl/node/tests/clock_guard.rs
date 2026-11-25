//! Garde-fou d'horloge (`deploiement.packaging#horloge`).

use std::sync::Mutex;

use s3m_node::clock_guard::*;
use s3m_node::dispersal_engine::DispersalState;
use s3m_node::exchange::{NodeService, PartnerState, UserAccount};
use s3m_node::inactivity::{purge_expired, DAY_S};

const NOW: u64 = 2_000_000_000;

#[test]
fn a_jump_of_more_than_a_day_is_detected() {
    assert_eq!(jump(NOW, 30, NOW + 30), None);
    assert_eq!(jump(NOW, 30, NOW + 30 + 3_600), None, "une heure : tolérée");
    assert_eq!(jump(NOW, 30, NOW + 30 + 365 * DAY_S), Some(365 * DAY_S as i64));
    assert_eq!(jump(NOW, 30, NOW - 2 * DAY_S), Some(-(2 * DAY_S as i64) - 30));
}

#[test]
fn a_frozen_clock_deletes_nothing_until_confirmed() {
    let mut s = NodeService::new([9; 32]);
    let u = [1; 32];
    s.users.insert(u, UserAccount { salt: vec![7; 16], quota_bytes: 1, used_bytes: 0, root: [0; 32] });
    s.auto_attached.insert(u);
    s.last_active.insert(u, NOW - 400 * DAY_S);
    s.partners.insert([2; 32], PartnerState { last_seen: 1, ..Default::default() });
    let f = vec![3u8; 65_536];
    let h = s3m_core::symmetric_suite::hash_sha256(&f);
    s.store.put(s3m_node::chunk_store::Space::Fragment, &[2; 32], &h, &f).unwrap();
    s.clock_freeze = Some(Freeze { at: NOW, jump_s: 365 * DAY_S as i64, reason: "test".into() });
    let service = Mutex::new(s);
    let mut state = DispersalState::default();
    assert!(purge_expired(&service, &mut state, NOW).is_empty());
    assert_eq!(service.lock().unwrap().purge_silent_partners(NOW), 0);
    assert_eq!(service.lock().unwrap().purge_emergency(NOW), 0);
    assert!(service.lock().unwrap().users.contains_key(&u));
    // Confirmation de l'opérateur : les suppressions reprennent.
    service.lock().unwrap().clock_freeze = None;
    assert_eq!(purge_expired(&service, &mut state, NOW), vec![u]);
    assert_eq!(service.lock().unwrap().purge_silent_partners(NOW), 1);
}
