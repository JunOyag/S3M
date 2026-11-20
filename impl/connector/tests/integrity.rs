//! Invariants de `protocols.integrite-lecture`.

use std::cell::Cell;

use s3m_connector::integrity::*;
use s3m_core::symmetric_suite::hash_sha256;

/// Source de test : le Nœud rend `node_answers[i]` à la i-ième demande.
struct Fake {
    node_answers: Vec<Option<Vec<u8>>>,
    calls: Cell<usize>,
    rebuilt: Option<Vec<u8>>,
    reconstructions: Cell<usize>,
}

impl BlockSource for Fake {
    fn fetch_from_node(&self, _: &BlockHash) -> Option<Vec<u8>> {
        let i = self.calls.get();
        self.calls.set(i + 1);
        self.node_answers.get(i).cloned().flatten()
    }
    fn reconstruct(&self, _: &BlockHash) -> Option<Vec<u8>> {
        self.reconstructions.set(self.reconstructions.get() + 1);
        self.rebuilt.clone()
    }
}

fn fake(node: Vec<Option<Vec<u8>>>, rebuilt: Option<Vec<u8>>) -> Fake {
    Fake {
        node_answers: node,
        calls: Cell::new(0),
        rebuilt,
        reconstructions: Cell::new(0),
    }
}

const GOOD: &[u8] = b"bloc chiffre correct";

fn h() -> BlockHash {
    hash_sha256(GOOD)
}

#[test]
fn correct_block_is_served_without_reconstruction() {
    let src = fake(vec![Some(GOOD.to_vec())], None);
    assert_eq!(
        fetch_verified(&src, &h(), 1),
        ReadOutcome::Ok(GOOD.to_vec())
    );
    assert_eq!(src.reconstructions.get(), 0);
}

/// Incohérence transitoire : la nouvelle tentative auprès du Nœud suffit.
#[test]
fn transient_mismatch_is_resolved_by_retrying_the_node() {
    let src = fake(vec![Some(b"corrompu".to_vec()), Some(GOOD.to_vec())], None);
    assert_eq!(
        fetch_verified(&src, &h(), 1),
        ReadOutcome::Ok(GOOD.to_vec())
    );
    assert_eq!(src.reconstructions.get(), 0);
}

/// Copie du Nœud corrompue : la version reconstruite est servie et un
/// incident est journalisé pour le Nœud.
#[test]
fn persistent_mismatch_is_repaired_from_parity_and_reported() {
    let src = fake(
        vec![Some(b"x".to_vec()), Some(b"x".to_vec())],
        Some(GOOD.to_vec()),
    );
    let mut log = IntegrityLog::default();
    assert_eq!(log.read(&src, &h(), 1), Some(GOOD.to_vec()));
    assert_eq!(log.pending_incidents, vec![Incident { block_hash: h() }]);
    assert!(log.corrupted.is_empty());
}

/// Reconstruction impossible ou toujours incohérente : bloc irrécupérable,
/// marqué corrompu localement.
#[test]
fn unrecoverable_block_is_marked_corrupted() {
    for rebuilt in [None, Some(b"faux".to_vec())] {
        let src = fake(vec![None, None], rebuilt);
        let mut log = IntegrityLog::default();
        assert_eq!(log.read(&src, &h(), 1), None);
        assert!(log.corrupted.contains(&h()));
        assert!(log.pending_incidents.is_empty());
    }
}

/// `securite.integrite-autoreparation`, partie connector : la version
/// reconstruite est retransmise au Nœud — même si le Nœud est joignable.
#[test]
fn reconstructed_block_is_queued_for_retransmission_to_the_node() {
    let src = fake(
        vec![Some(b"x".to_vec()), Some(b"x".to_vec())],
        Some(GOOD.to_vec()),
    );
    let mut log = IntegrityLog::default();
    log.read(&src, &h(), 1);
    assert_eq!(
        log.pending_repairs,
        vec![RepairRequest {
            block_hash: h(),
            block: GOOD.to_vec()
        }]
    );
}
