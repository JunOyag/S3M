//! Tests de `deploiement.pseudos`, côté Connecteur.

use s3m_connector::channel::Names;
use s3m_protocol::pseudo::fingerprint;

#[test]
fn local_node_label_wins_over_the_published_name_and_fingerprint_always_shows() {
    let node = [3u8; 32];
    let fp = fingerprint(&node);
    let mut n = Names::default();
    assert_eq!(n.node_display(&node), fp);
    n.node_name = Some("Nœud de Paul".into());
    assert_eq!(n.node_display(&node), format!("Nœud de Paul · {fp}"));
    n.adopt(" Perso\n", "Maison");
    assert_eq!(n.pseudo, "Perso");
    assert_eq!(n.node_display(&node), format!("Maison · {fp}"));
    // Les noms survivent au redémarrage (names.json).
    let back: Names = serde_json::from_str(&serde_json::to_string(&n).unwrap()).unwrap();
    assert_eq!(back, n);
}
