//! Invariants de `protocols.dispersion-transactionnelle`.

use std::collections::HashSet;

use s3m_node::dispersion::*;

const K: usize = 4;

fn id(n: u8) -> StripeId {
    [n; 32]
}

/// Deux feuilles, un niveau intermédiaire, une racine.
fn tx() -> DispersalTransaction {
    DispersalTransaction::new(K, vec![vec![id(1), id(2)], vec![id(10)], vec![id(20)]]).unwrap()
}

fn confirm_all(t: &mut DispersalTransaction, s: StripeId, n: u16) {
    for p in 0..n {
        t.confirm(s, p).unwrap();
    }
}

/// Seuil k+2 : le parent ne devient dispersable qu'avec k+2 confirmations
/// de partenaires distincts sur chaque stripe du niveau inférieur.
#[test]
fn parent_waits_for_k_plus_2_confirmations_on_every_child() {
    let mut t = tx();
    assert_eq!(t.threshold(), 6);
    assert_eq!(t.next_to_disperse(), vec![id(1), id(2)]);
    t.mark_dispersed(id(1)).unwrap();
    t.mark_dispersed(id(2)).unwrap();
    confirm_all(&mut t, id(1), 6);
    confirm_all(&mut t, id(2), 5);
    assert!(t.next_to_disperse().is_empty());
    assert_eq!(t.mark_dispersed(id(10)), Err(DispersionError::OutOfOrder));
    // Une confirmation répétée du même partenaire ne compte pas.
    t.confirm(id(2), 0).unwrap();
    assert!(t.next_to_disperse().is_empty());
    t.confirm(id(2), 5).unwrap();
    assert_eq!(t.next_to_disperse(), vec![id(10)]);
}

/// Dispersion ascendante jusqu'à la racine ; commit refusé avant la
/// confirmation de la racine.
#[test]
fn bottom_up_then_commit_only_after_root_confirmed() {
    let mut t = tx();
    for s in [id(1), id(2)] {
        t.mark_dispersed(s).unwrap();
        confirm_all(&mut t, s, 6);
    }
    t.mark_dispersed(id(10)).unwrap();
    confirm_all(&mut t, id(10), 6);
    t.mark_dispersed(id(20)).unwrap();
    assert_eq!(t.commit(100), Err(DispersionError::RootNotConfirmed));
    confirm_all(&mut t, id(20), 6);
    assert_eq!(t.commit(100), Ok(id(20)));
    assert!(t.is_committed());
    assert!(t.next_to_disperse().is_empty());
}

/// Reprise après crash : rejouer le journal (même deux fois) redonne le
/// même état, sans doublon.
#[test]
fn journal_replay_is_idempotent() {
    let mut t = tx();
    t.mark_dispersed(id(1)).unwrap();
    confirm_all(&mut t, id(1), 6);
    t.mark_dispersed(id(2)).unwrap();
    confirm_all(&mut t, id(2), 6);
    let journal = t.journal().to_vec();

    let mut resumed = tx();
    resumed.replay(&journal).unwrap();
    resumed.replay(&journal).unwrap();
    assert_eq!(resumed.journal(), journal.as_slice());
    assert_eq!(resumed.next_to_disperse(), vec![id(10)]);
}

/// Purge différée : seulement après commit et délai de grâce, et seulement
/// les blocs absents de la nouvelle version.
#[test]
fn orphans_are_purged_after_grace_period_only() {
    let mut t = tx();
    for s in [id(1), id(2)] {
        t.mark_dispersed(s).unwrap();
        confirm_all(&mut t, s, 6);
    }
    for s in [id(10), id(20)] {
        t.mark_dispersed(s).unwrap();
        confirm_all(&mut t, s, 6);
    }
    let old: HashSet<_> = [[1u8; 32], [2; 32], [3; 32]].into();
    let new: HashSet<_> = [[2u8; 32], [4; 32]].into();
    assert!(
        t.purge_due(&old, &new, 1_000, 60).is_empty(),
        "pas encore commité"
    );
    t.commit(1_000).unwrap();
    assert!(
        t.purge_due(&old, &new, 1_059, 60).is_empty(),
        "grâce en cours"
    );
    assert_eq!(t.purge_due(&old, &new, 1_060, 60), vec![[1u8; 32], [3; 32]]);
}

#[test]
fn malformed_transactions_and_unknown_stripes_are_rejected() {
    assert!(DispersalTransaction::new(K, vec![]).is_err());
    assert!(DispersalTransaction::new(K, vec![vec![id(1), id(2)]]).is_err());
    let mut t = tx();
    assert_eq!(t.confirm(id(1), 0), Err(DispersionError::OutOfOrder));
    assert_eq!(
        t.mark_dispersed(id(99)),
        Err(DispersionError::UnknownStripe)
    );
}
