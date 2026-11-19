//! Invariants de `protocols.write-queue`.

use p2p_storage_connector::fs::Entry;
use p2p_storage_connector::write_queue::*;

fn entry(name: &str, first: u8, modified_at: u64) -> Entry {
    Entry {
        name: name.into(),
        size_bytes: 10,
        mime_type: "text/plain".into(),
        first_block_hash: [first; 32],
        encryption_salt: [1; 16],
        key_version: 1,
        permissions: 0o644,
        created_at: 1,
        modified_at,
    }
}

fn wb(ts: u64, path: &str, h: u8) -> Queued {
    Queued {
        timestamp: ts,
        fs_path: path.into(),
        op: Op::WriteBlock {
            block_hash: [h; 32],
        },
    }
}

fn ue(ts: u64, path: &str, first: u8) -> Queued {
    Queued {
        timestamp: ts,
        fs_path: path.into(),
        op: Op::UpdateEntry {
            entry: entry(path, first, ts),
        },
    }
}

/// Sink de test : confirme tout, sauf à partir de la n-ième mutation.
struct Sink {
    accepted: Vec<Queued>,
    fail_at: usize,
}

impl ReplaySink for Sink {
    fn apply(&mut self, m: &Queued) -> bool {
        if self.accepted.len() == self.fail_at {
            return false;
        }
        self.accepted.push(m.clone());
        true
    }
}

#[test]
fn q_max_budget_is_enforced() {
    let mut q = WriteQueue::new([0; 32], 2 * BLOCK_BYTES);
    q.enqueue(wb(1, "/a", 1)).unwrap();
    q.enqueue(wb(2, "/a", 2)).unwrap();
    assert_eq!(q.enqueue(wb(3, "/a", 3)), Err(QueueError::QueueFull));
    assert_eq!(DEFAULT_Q_MAX, 4 * 1024 * 1024 * 1024);
}

/// Un `update_entry` ne peut référencer qu'un bloc écrit avant lui.
#[test]
fn update_entry_without_prior_block_write_is_refused() {
    let mut q = WriteQueue::new([0; 32], DEFAULT_Q_MAX);
    assert_eq!(q.enqueue(ue(5, "/a", 9)), Err(QueueError::OrphanPointer));
    q.enqueue(wb(6, "/a", 9)).unwrap();
    assert_eq!(q.enqueue(ue(5, "/a", 9)), Err(QueueError::OrphanPointer));
    q.enqueue(ue(7, "/a", 9)).unwrap();
}

/// Rejeu strictement par horodatage, arrêt à la première mutation non
/// confirmée : rien n'est réordonné ni sauté.
#[test]
fn replay_is_strictly_ordered_and_stops_at_first_failure() {
    let mut q = WriteQueue::new([0; 32], DEFAULT_Q_MAX);
    for m in [
        wb(1, "/a", 1),
        wb(2, "/a", 2),
        ue(3, "/a", 1),
        wb(4, "/b", 4),
        ue(5, "/b", 4),
    ] {
        q.enqueue(m).unwrap();
    }
    let mut sink = Sink {
        accepted: vec![],
        fail_at: 3,
    };
    assert_eq!(q.replay(&mut sink), 3);
    let ts: Vec<_> = sink.accepted.iter().map(|m| m.timestamp).collect();
    assert_eq!(ts, vec![1, 2, 3]);
    assert_eq!(q.mutations.len(), 2);
    let mut sink = Sink {
        accepted: vec![],
        fail_at: usize::MAX,
    };
    assert_eq!(q.replay(&mut sink), 2);
    assert!(q.mutations.is_empty());
}

/// Conflit multi-appareils : détecté par `base_fs_root_hash` ; dernier écrit
/// gagne, le perdant est conservé sous un nom suffixé.
#[test]
fn conflict_is_detected_and_resolved_last_writer_wins_keeping_loser() {
    let q = WriteQueue::new([1; 32], DEFAULT_Q_MAX);
    assert!(!q.has_conflict(&[1; 32]));
    assert!(q.has_conflict(&[2; 32]));
    let local = entry("rapport.txt", 1, 200);
    let remote = entry("rapport.txt", 2, 100);
    let (winner, kept) = resolve_conflict(&local, &remote);
    assert_eq!(winner, local);
    assert_eq!(kept.name, "rapport.txt.conflit-100");
    assert_eq!(kept.first_block_hash, remote.first_block_hash);
}

/// Vue fusionnée pendant la panne et persistance au format `fs.WriteQueue`.
#[test]
fn merged_view_and_persistence_roundtrip() {
    let mut q = WriteQueue::new([3; 32], DEFAULT_Q_MAX);
    q.enqueue(wb(1, "/a", 1)).unwrap();
    q.enqueue(ue(2, "/a", 1)).unwrap();
    q.enqueue(Queued {
        timestamp: 3,
        fs_path: "/b".into(),
        op: Op::DeleteEntry {
            blocks_to_delete: vec![[7; 32], [8; 32]],
        },
    })
    .unwrap();
    assert_eq!(q.view("/a").unwrap().unwrap().first_block_hash, [1; 32]);
    assert_eq!(q.view("/b"), Some(None));
    assert_eq!(q.view("/c"), None);
    let back = WriteQueue::decode(&q.encode(), DEFAULT_Q_MAX).unwrap();
    assert_eq!(back, q);
}
