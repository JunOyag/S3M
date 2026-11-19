//! Invariants de `protocols.volatilite-reparation`.

use std::collections::BTreeSet;

use p2p_storage_core::erasure::{encode_parity, reconstruct_data};
use p2p_storage_node::volatility::*;

const K: usize = 4;
const DAY: u64 = 86_400;
const NOW: u64 = 1_000 * DAY;

fn holders(down: &[usize]) -> Vec<Holder> {
    (K..K + 12)
        .map(|i| Holder {
            index: i,
            partner: i as u16,
            last_seen: if down.contains(&i) {
                NOW - 3 * DAY
            } else {
                NOW
            },
        })
        .collect()
}

/// Au-dessus de k+2 fragments disponibles : rien à faire ; en dessous :
/// réparation des seuls fragments indisponibles.
#[test]
fn repair_triggers_when_available_parity_drops_below_k_plus_2() {
    let few_down: Vec<usize> = (4..10).collect(); // 6 indisponibles, 6 disponibles
    assert!(analyze(&holders(&few_down), K, NOW, DAY).repair.is_empty());
    let many_down: Vec<usize> = (4..11).collect(); // 7 indisponibles, 5 disponibles
    assert_eq!(analyze(&holders(&many_down), K, NOW, DAY).repair, many_down);
}

#[test]
fn partners_offline_more_than_six_months_are_purged() {
    let mut h = holders(&[]);
    h[0].last_seen = NOW - PURGE_AFTER_S - 1;
    h[1].last_seen = NOW - PURGE_AFTER_S;
    assert_eq!(analyze(&h, K, NOW, DAY).purge, vec![4]);
}

/// Les fragments régénérés depuis la copie locale des k blocs sont
/// identiques aux originaux ; ils vont chez des partenaires nouveaux et
/// distincts.
#[test]
fn regenerated_fragments_match_originals_and_go_to_new_distinct_partners() {
    let data: Vec<Vec<u8>> = (0..K).map(|i| vec![i as u8; 1024]).collect();
    let refs: Vec<&[u8]> = data.iter().map(|d| d.as_slice()).collect();
    let original = encode_parity(&refs, 3).unwrap();
    let regenerated = encode_parity(&refs, 3).unwrap();
    assert_eq!(regenerated[3], original[3]);
    // Et la stripe reste reconstructible depuis k fragments.
    let mut shards: Vec<Option<Vec<u8>>> = vec![None; 16];
    for i in [5, 9, 12, 15] {
        shards[i] = Some(original[i - K].clone());
    }
    assert_eq!(reconstruct_data(shards, K, 3).unwrap(), data);

    let h = holders(&[4, 5]);
    let picks = choose_new_partners(&h, &[4, 5], &[4, 100, 101]).unwrap();
    assert_eq!(picks, vec![(4, 100), (5, 101)]);
    assert_eq!(choose_new_partners(&h, &[4, 5], &[100]), None);
}

#[test]
fn surplus_is_resolved_when_the_original_partner_returns() {
    let temps = [
        TemporaryCopy {
            index: 4,
            original_partner: 4,
            temporary_partner: 100,
        },
        TemporaryCopy {
            index: 5,
            original_partner: 5,
            temporary_partner: 101,
        },
    ];
    let back: BTreeSet<u16> = [5].into();
    assert_eq!(surplus_to_delete(&temps, &back), vec![temps[1]]);
}
