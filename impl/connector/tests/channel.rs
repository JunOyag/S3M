//! Tests de `protocols.canal-noeud`, côté Connecteur.

use s3m_connector::channel::*;
use s3m_protocol::exchange::Id;
use s3m_protocol::message::{
    alert_entry_envelope, open_alert_entry, sign_message, Kind, NodeMessage,
};

const PRIV_NODE: [u8; 32] = [1; 32];
const PRIV_ANNOUNCE: [u8; 32] = [2; 32];
const PRIV_THIEF: [u8; 32] = [3; 32];

fn pk(s: &[u8; 32]) -> Id {
    ed25519_dalek::SigningKey::from_bytes(s)
        .verifying_key()
        .to_bytes()
}

fn m(seq: u64, kind: Kind, successor: Option<Id>) -> NodeMessage {
    NodeMessage {
        node_id: pk(&PRIV_NODE),
        seq,
        timestamp: 100,
        kind,
        text: "texte".into(),
        successor,
    }
}

#[test]
fn first_announce_key_is_pinned_and_a_later_one_is_ignored() {
    let node = pk(&PRIV_NODE);
    let mut c = ChannelState::default();
    c.pin(&node, None);
    c.pin(&node, Some(pk(&PRIV_ANNOUNCE)));
    c.pin(&node, Some(pk(&PRIV_THIEF)));
    assert_eq!(c.announce, Some(pk(&PRIV_ANNOUNCE)));
    // Alerte du voleur (seed volée) : signée par la clé du Nœud ou par sa propre clé.
    assert!(!c.accept(&sign_message(&PRIV_NODE, &m(1, Kind::Alert, Some([9; 32])))));
    assert!(!c.accept(&sign_message(
        &PRIV_THIEF,
        &m(1, Kind::Alert, Some([9; 32]))
    )));
    assert!(!c.distrusts(&node));
    assert!(c.accept(&sign_message(&PRIV_NODE, &m(1, Kind::Info, None))));
    assert!(!c.accept(&sign_message(&PRIV_NODE, &m(1, Kind::Info, None))));
    assert!(c.accept(&sign_message(
        &PRIV_ANNOUNCE,
        &m(1, Kind::Alert, Some([9; 32]))
    )));
    assert!(c.distrusts(&node) && !c.alert_acknowledged);
    assert_eq!(c.successor(), Some([9; 32]));
    assert_eq!(c.received.len(), 2);
    // Autre Nœud : tout est oublié sauf les messages envoyés.
    c.sent.push((1, "bonjour".into()));
    c.pin(&[7; 32], None);
    assert!(c.alert.is_none() && c.announce.is_none() && c.received.is_empty());
    assert_eq!(c.sent.len(), 1);
}

#[test]
fn alert_from_the_directory_is_accepted_once_and_republished_unchanged() {
    let node = pk(&PRIV_NODE);
    let announce = pk(&PRIV_ANNOUNCE);
    let mut c = ChannelState::default();
    c.pin(&node, Some(announce));
    let alert = sign_message(&PRIV_ANNOUNCE, &m(1, Kind::Alert, None));
    let env = alert_entry_envelope(&PRIV_ANNOUNCE, &alert, 100);
    let (k, a) = open_alert_entry(&env, 200).unwrap();
    assert!(!c.accept_entry(&pk(&PRIV_THIEF), &a, env.clone()));
    assert!(c.accept_entry(&k, &a, env.clone()));
    assert!(!c.accept_entry(&k, &a, env.clone()));
    assert!(c.distrusts(&node));
    assert_eq!(c.republish_due(200), Some(env.clone()));
    c.alert_republished_at = 200;
    assert_eq!(c.republish_due(201), None);
    assert_eq!(c.republish_due(200 + 2_592_000), Some(env));
}
