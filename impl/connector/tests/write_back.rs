//! Invariants de `protocols.ecriture-differee`.

use s3m_connector::write_back::*;

const MIB: u64 = 1024 * 1024;

/// D = clamp(60 s + 0,5 s/MiO, 60, 300) : 1 MiO ≈ 1 min ; 100 MiO ≈ 1 min
/// 50 s ; plafond de 5 min dès 480 MiO.
#[test]
fn debounce_delay_follows_the_spec_formula() {
    let c = WriteBackConfig::default();
    assert_eq!(debounce_delay_s(&c, 0), 60);
    assert_eq!(debounce_delay_s(&c, MIB), 60);
    assert_eq!(debounce_delay_s(&c, 100 * MIB), 110);
    assert_eq!(debounce_delay_s(&c, 480 * MIB), 300);
    assert_eq!(debounce_delay_s(&c, 10_000 * MIB), 300);
}

/// Le minuteur redémarre à chaque écriture ; fsync ne déclenche rien.
#[test]
fn timer_restarts_on_each_write_and_fsync_does_not_trigger() {
    let mut s = Scheduler::new(WriteBackConfig::default());
    s.on_write("/a", MIB, 0);
    s.on_write("/a", MIB, 50);
    s.on_fsync("/a");
    assert!(s.take_due(100).is_empty());
    assert_eq!(s.take_due(110), vec!["/a".to_string()]);
    assert_eq!(s.pending_count(), 0);
}

/// Écritures continues : la synchronisation part au plus tard 15 min après
/// la première écriture non synchronisée.
#[test]
fn continuous_writes_are_bounded_by_the_15_minute_max_wait() {
    let mut s = Scheduler::new(WriteBackConfig::default());
    for t in (0..=890).step_by(10) {
        s.on_write("/journal.log", MIB, t);
    }
    assert!(s.take_due(899).is_empty());
    assert_eq!(s.take_due(900), vec!["/journal.log".to_string()]);
}

/// Démontage / arrêt / « synchroniser maintenant » : tout part immédiatement.
#[test]
fn sync_now_flushes_everything_immediately() {
    let mut s = Scheduler::new(WriteBackConfig::default());
    s.on_write("/a", MIB, 0);
    s.on_write("/b", 400 * MIB, 0);
    s.sync_now();
    assert_eq!(s.take_due(1), vec!["/a".to_string(), "/b".to_string()]);
}

/// Espace de travail : plafonné par le disque libre moins la réserve,
/// indépendant de Q_max ; à défaut, « disque plein ».
#[test]
fn workspace_budget_is_disk_minus_reserve() {
    let s = Scheduler::new(WriteBackConfig {
        workspace_reserve_bytes: 10 * MIB,
        ..Default::default()
    });
    assert!(s.reserve_workspace(80 * MIB, 100 * MIB, 10 * MIB).is_ok());
    assert_eq!(
        s.reserve_workspace(81 * MIB, 100 * MIB, 10 * MIB),
        Err(DiskFull)
    );
}

#[test]
fn old_chain_is_tombstoned_only_after_new_chain_is_confirmed() {
    assert_eq!(old_chain_to_tombstone(false, vec![1]), None);
    assert_eq!(old_chain_to_tombstone(true, vec![1]), Some(vec![1]));
}
