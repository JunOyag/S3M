//! Tests de `deploiement.pseudos`, côté Nœud.

use std::collections::HashMap;

use s3m_node::daemon::SavedState;
use s3m_node::exchange::*;

#[test]
fn node_name_and_user_labels_survive_a_restart() {
    let mut s = NodeService::new([1; 32]);
    s.name = Some("Nœud de Paul".into());
    s.user_labels.insert([4; 32], "Marie".into());
    let saved = SavedState::capture(&s, &HashMap::new());
    let json = serde_json::to_string(&saved).unwrap();
    let back: SavedState = serde_json::from_str(&json).unwrap();
    let mut r = NodeService::new([1; 32]);
    back.restore(&mut r).unwrap();
    assert_eq!(r.name.as_deref(), Some("Nœud de Paul"));
    assert_eq!(
        r.user_labels.get(&[4; 32]).map(String::as_str),
        Some("Marie")
    );
    // Un ancien état sans ces champs reste lisible.
    let old: SavedState = serde_json::from_str(
        r#"{"users":[],"partners":[],"previous_node_ids":[],"incidents":[],"delegations":[]}"#,
    )
    .unwrap();
    assert!(old.name.is_none() && old.user_labels.is_empty());
}
