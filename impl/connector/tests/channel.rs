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
        ..Default::default()
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
    assert!(!c.accept(
        &sign_message(&PRIV_NODE, &m(1, Kind::Alert, Some([9; 32]))),
        None
    ));
    assert!(!c.accept(
        &sign_message(&PRIV_THIEF, &m(1, Kind::Alert, Some([9; 32]))),
        None
    ));
    assert!(!c.distrusts(&node));
    assert!(c.accept(&sign_message(&PRIV_NODE, &m(1, Kind::Info, None)), None));
    assert!(!c.accept(&sign_message(&PRIV_NODE, &m(1, Kind::Info, None)), None));
    assert!(c.accept(
        &sign_message(&PRIV_ANNOUNCE, &m(1, Kind::Alert, Some([9; 32]))),
        None
    ));
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

/// Message adressé à un autre Utilisateur rejeté ; remplacement de la clé
/// d'annonce jamais appliqué sans accord, refus = ancienne clé gardée.
#[test]
fn addressed_messages_and_announce_replacement_need_the_user() {
    let node = pk(&PRIV_NODE);
    let me = [0xa1; 32];
    let mut c = ChannelState::default();
    c.pin(&node, Some(pk(&PRIV_ANNOUNCE)));
    let mut other = m(1, Kind::Info, None);
    other.recipient = Some([0xb2; 32]);
    assert!(!c.accept(&sign_message(&PRIV_NODE, &other), Some(&me)));
    let mut mine = m(2, Kind::Info, None);
    mine.recipient = Some(me);
    assert!(c.accept(&sign_message(&PRIV_NODE, &mine), Some(&me)));
    assert!(c.received.last().unwrap().personal);
    // Remplacement proposé (seed volée ou opérateur) : en attente.
    let mut rep = m(3, Kind::Info, None);
    rep.announce_replacement = Some(pk(&PRIV_THIEF));
    assert!(c.accept(&sign_message(&PRIV_NODE, &rep), Some(&me)));
    assert_eq!(c.announce, Some(pk(&PRIV_ANNOUNCE)));
    assert_eq!(c.pending_announce, Some((pk(&PRIV_THIEF), 3)));
    assert_eq!(c.decide_replacement(false), Some(pk(&PRIV_ANNOUNCE)));
    assert!(c.pending_announce.is_none());
    // Nouvelle demande, acceptée : la nouvelle clé signe désormais les alertes.
    let mut rep2 = m(4, Kind::Info, None);
    rep2.announce_replacement = Some(pk(&PRIV_THIEF));
    assert!(c.accept(&sign_message(&PRIV_NODE, &rep2), Some(&me)));
    assert_eq!(c.decide_replacement(true), Some(pk(&PRIV_THIEF)));
    assert!(c.accept(
        &sign_message(&PRIV_THIEF, &m(1, Kind::Alert, None)),
        Some(&me)
    ));
    assert!(!c.accept(
        &sign_message(&PRIV_ANNOUNCE, &m(2, Kind::Alert, None)),
        Some(&me)
    ));
    assert_eq!(c.received_total, 4, "compteur des notifications");
}

/// Messages non lus du Connecteur : nouveaux non lus, marqués lus un à un
/// ou tous ; un message conservé avant cette notion compte comme lu.
#[test]
fn node_messages_are_unread_until_opened() {
    let node = pk(&PRIV_NODE);
    let mut c = ChannelState::default();
    c.pin(&node, None);
    assert!(c.accept(&sign_message(&PRIV_NODE, &m(1, Kind::Info, None)), None));
    assert!(c.accept(&sign_message(&PRIV_NODE, &m(2, Kind::Info, None)), None));
    assert_eq!(c.unread(), 2);
    assert!(c.mark_read(Kind::Info, 1));
    assert!(!c.mark_read(Kind::Info, 1));
    assert!(!c.mark_read(Kind::Alert, 2), "autre sorte");
    assert_eq!(c.unread(), 1);
    assert_eq!(c.mark_all_read(), 1);
    assert_eq!(c.unread(), 0);
    let old: Received = serde_json::from_str(
        r#"{"kind":"Info","seq":1,"timestamp":1,"text":"x","successor":null}"#,
    )
    .unwrap();
    assert!(old.read, "ancien message : lu");
}
