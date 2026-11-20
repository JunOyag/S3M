//! Invariants de `protocols.index-adaptatif`.

use s3m_protocol::fb::dispersal::IndexNode;
use s3m_protocol::index::*;

/// Facteur de branchement mesuré pour N = 16 (k = 4, coef = 3) ; la spec
/// estimait « ≤ 75 » ; la mesure sur les types générés donne 68.
#[test]
fn branching_factor_is_measured_for_n16() {
    let f = measure_branching_factor(16);
    assert_eq!(BRANCHING_FACTOR, f, "valeur mesurée : {f}");
}

/// 1 TiO (~4,19 M stripes) : 3 niveaux d'indirection sous la racine, avec
/// le facteur mesuré.
#[test]
fn one_tib_needs_three_indirection_levels() {
    let shape = tree_shape(4_194_304, BRANCHING_FACTOR);
    assert_eq!(shape, vec![61_681, 908, 14, 1]);
    assert_eq!(shape.len() - 1, 3);
}

/// La profondeur ne grandit que si nécessaire.
#[test]
fn depth_grows_only_when_needed() {
    let f = BRANCHING_FACTOR;
    assert_eq!(tree_shape(1, f), vec![1]);
    assert_eq!(tree_shape(f, f), vec![1]);
    assert_eq!(tree_shape(f + 1, f), vec![2, 1]);
    assert_eq!(tree_shape(f * f + 1, f), vec![f + 1, 2, 1]);
}

#[test]
fn grouping_covers_every_item_once_and_ends_in_one_root() {
    let levels = group_levels(1000, 10);
    assert_eq!(levels.last().unwrap().len(), 1);
    let leaves = &levels[0];
    assert_eq!(leaves.iter().map(|r| r.len()).sum::<usize>(), 1000);
    assert!(leaves.iter().all(|r| r.len() <= 10));
    assert_eq!(levels.len(), tree_shape(1000, 10).len());
}

/// Chiffrement d'un nœud d'index : sel par nœud, aller-retour, autre sel →
/// rejet ; le buffer reste lisible après déchiffrement.
#[test]
fn index_node_is_sealed_per_node_salt() {
    let content = [0x42; 32];
    let header = [0, 1];
    let bytes = {
        let mut fbb = flatbuffers::FlatBufferBuilder::new();
        let n = s3m_protocol::fb::dispersal::IndexNode::create(
            &mut fbb,
            &s3m_protocol::fb::dispersal::IndexNodeArgs {
                is_leaf: true,
                ..Default::default()
            },
        );
        fbb.finish_minimal(n);
        fbb.finished_data().to_vec()
    };
    let frame = seal_index_node(&content, &[1; 16], &header, &[9; 12], &bytes).unwrap();
    assert_eq!(frame.len(), 65_536);
    let clear = open_index_node(&content, &[1; 16], &header, &frame).unwrap();
    assert_eq!(&clear[..bytes.len()], bytes.as_slice());
    let node = flatbuffers::root::<IndexNode>(&clear[..bytes.len()]).unwrap();
    assert!(node.is_leaf());
    assert!(open_index_node(&content, &[2; 16], &header, &frame).is_err());
}
