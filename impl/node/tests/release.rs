//! Libération des blocs d'un Utilisateur (`protocols.echange-blocs`
//! § Libération) : quota rendu, liste, annulation, effacement différé.

use std::sync::Mutex;

use s3m_node::chunk_store::Space;
use s3m_node::dispersal_engine::*;
use s3m_node::exchange::*;

const NODE: [u8; 32] = [0x21; 32];
const USER: [u8; 32] = [0x31; 32];
const OTHER: [u8; 32] = [0x41; 32];
const BLOCK: usize = 65_536;

fn block(n: u8) -> Vec<u8> {
    vec![n; BLOCK]
}

#[test]
fn released_blocks_refund_quota_and_are_erased_after_the_grace_period() {
    let mut s = NodeService::new(NODE);
    // Sans historique : seul le délai court s'applique.
    s.history_retention_s = 0;
    for u in [USER, OTHER] {
        s.users.insert(
            u,
            UserAccount {
                salt: vec![7; 16],
                quota_bytes: 10 * BLOCK as u64,
                used_bytes: 0,
                root: [0; 32],
            },
        );
    }
    let h: Vec<[u8; 32]> = (1..=6u8)
        .map(|n| s.put_user_block(&USER, &block(n)).unwrap())
        .collect();
    let foreign = s.put_user_block(&OTHER, &block(99)).unwrap();
    assert_eq!(s.users[&USER].used_bytes, 6 * BLOCK as u64);

    // Libération : quota rendu aussitôt ; inconnu, étranger, doublon ignorés.
    let freed = s.release_user_blocks(
        &USER,
        &[h[0], h[1], h[2], h[3], foreign, [9; 32], h[0]],
        1_000,
    );
    assert_eq!(freed, 4);
    assert_eq!(s.users[&USER].used_bytes, 2 * BLOCK as u64);
    assert_eq!(
        s.users[&OTHER].used_bytes, BLOCK as u64,
        "rien chez l'autre"
    );
    assert!(
        s.store.get(Space::UserBlock, &h[0]).is_some(),
        "encore lisible"
    );
    // Liste : blocs encore comptés seulement, par pages.
    let (page, more) = s.list_user_blocks(&USER, &[], 1);
    assert!(more && page.len() == 1);
    let (rest, more) = s.list_user_blocks(&USER, &page[0], 10);
    assert!(!more);
    let mut all: Vec<[u8; 32]> = [page, rest].concat();
    all.sort();
    let mut want = vec![h[4], h[5]];
    want.sort();
    assert_eq!(all, want);
    // Renvoi d'un bloc libéré : il sert de nouveau.
    s.put_user_block(&USER, &block(4)).unwrap();
    assert_eq!(s.users[&USER].used_bytes, 3 * BLOCK as u64);
    assert!(!s.released[&USER].contains_key(&h[3]));

    // Dispersion : h0+h1 dans un stripe (entièrement libéré), h2+h4 dans un
    // autre (libéré en partie) ; h5 en attente.
    let hx = |x: &[u8; 32]| hex::encode(x);
    let mut state = DispersalState::default();
    state.users.insert(
        hx(&USER),
        UserDispersal {
            pending: vec![hx(&h[5])],
            stripes: vec![
                StripeRec {
                    id: "s1".into(),
                    data: vec![hx(&h[0]), hx(&h[1])],
                    padding: vec![false, false],
                    parity: vec![(2, "p1".into(), "partenaire".into())],
                    salt: None,
                },
                StripeRec {
                    id: "s2".into(),
                    data: vec![hx(&h[2]), hx(&h[4])],
                    padding: vec![false, false],
                    parity: vec![(2, "p2".into(), "partenaire".into())],
                    salt: None,
                },
            ],
            ..Default::default()
        },
    );
    s.release_user_blocks(&USER, &[h[5]], 1_000);
    let service = Mutex::new(s);
    // Avant le délai : rien n'est effacé.
    assert_eq!(
        purge_released(&service, &mut state, 1_000 + RELEASE_GRACE_S - 1),
        0
    );
    // Après : stripe s1 retiré (parité à purger), h5 retiré de l'attente ;
    // s2 gardé avec h2 (partiellement libéré).
    let erased = purge_released(&service, &mut state, 1_000 + RELEASE_GRACE_S);
    assert_eq!(erased, 3);
    let u = &state.users[&hx(&USER)];
    assert_eq!(u.stripes.len(), 1);
    assert_eq!(u.stripes[0].id, "s2");
    assert!(u.pending.is_empty());
    assert!(u.dirty, "index à republier");
    assert!(
        u.retired.iter().any(|r| r.hash == "p1"),
        "parité purgée chez le partenaire"
    );
    let s = service.lock().unwrap();
    for gone in [h[0], h[1], h[5]] {
        assert!(s.store.get(Space::UserBlock, &gone).is_none());
    }
    assert!(
        s.store.get(Space::UserBlock, &h[2]).is_some(),
        "stripe gardé"
    );
    assert!(s.released[&USER].contains_key(&h[2]));
}

/// Avec l'historique, un bloc libéré reste au moins la durée de conservation
/// des versions (une libération ne contourne pas la purge protégée par le
/// 2FA) ; une purge de l'historique ramène au délai court.
#[test]
fn released_blocks_outlive_the_history_unless_it_is_purged() {
    let mut s = NodeService::new(NODE);
    s.history_retention_s = 30 * 86_400;
    s.users.insert(USER, UserAccount { salt: vec![1; 16], quota_bytes: 1 << 30, used_bytes: 0, root: [0; 32] });
    let b = block(9);
    let h = s3m_core::symmetric_suite::hash_sha256(&b);
    s.store.put(s3m_node::chunk_store::Space::UserBlock, &USER, &h, &b).unwrap();
    s.release_user_blocks(&USER, &[h], 1_000);
    s.root_history.entry(USER).or_default().push(s3m_protocol::exchange::RootVersion { root: vec![1; 32], root_seal: vec![], valid_from: 800, replaced_at: 900 });
    let service = Mutex::new(s);
    let mut state = DispersalState::default();
    state.users.entry(hex::encode(USER)).or_default().pending.push(hex::encode(h));
    assert_eq!(purge_released(&service, &mut state, 1_000 + RELEASE_GRACE_S), 0, "gardé pour l'historique");
    service.lock().unwrap().purge_history(&USER, 0);
    assert_eq!(purge_released(&service, &mut state, 1_000 + RELEASE_GRACE_S), 1);
    assert!(!service.lock().unwrap().released.get(&USER).is_some_and(|r| r.contains_key(&h)), "effacé après la purge");
}
