//! Tests de `protocols.canal-noeud` (partie commune).

use s3m_protocol::dht::{accept_record, alert_dht_key};
use s3m_protocol::exchange::*;
use s3m_protocol::message::*;

fn pk(seed: &[u8; 32]) -> Id {
    ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes()
}

fn msg(node: &Id, seq: u64, kind: Kind, successor: Option<Id>) -> NodeMessage {
    NodeMessage {
        node_id: *node,
        seq,
        timestamp: 1_000 + seq,
        kind,
        text: "maintenance".into(),
        successor,
        ..Default::default()
    }
}

#[test]
fn info_is_signed_by_the_node_and_alert_only_by_the_pinned_announce_key() {
    let (priv_node, priv_announce, priv_thief) = ([1u8; 32], [2u8; 32], [3u8; 32]);
    let node = pk(&priv_node);
    let announce = pk(&priv_announce);
    let info = sign_message(&priv_node, &msg(&node, 1, Kind::Info, None));
    assert_eq!(verify_message(&info, &node, None).unwrap().seq, 1);
    assert_eq!(
        verify_message(&info, &[9; 32], None),
        Err(Refusal::Unauthorized)
    );
    // Une alerte signée par la clé du Nœud (seed volée) est refusée.
    let forged = sign_message(&priv_node, &msg(&node, 1, Kind::Alert, Some([7; 32])));
    assert_eq!(
        verify_message(&forged, &node, Some(&announce)),
        Err(Refusal::Unauthorized)
    );
    let thief = sign_message(&priv_thief, &msg(&node, 1, Kind::Alert, None));
    assert_eq!(
        verify_message(&thief, &node, Some(&announce)),
        Err(Refusal::Unauthorized)
    );
    let alert = sign_message(&priv_announce, &msg(&node, 1, Kind::Alert, Some([7; 32])));
    assert_eq!(
        verify_message(&alert, &node, None),
        Err(Refusal::Unauthorized)
    );
    let m = verify_message(&alert, &node, Some(&announce)).unwrap();
    assert_eq!(m.successor, Some([7; 32]));
    // Successeur réservé à l'alerte ; texte borné.
    let bad = sign_message(&priv_node, &msg(&node, 2, Kind::Info, Some([7; 32])));
    assert_eq!(verify_message(&bad, &node, None), Err(Refusal::Malformed));
    let mut long = msg(&node, 3, Kind::Info, None);
    long.text = "x".repeat(MAX_TEXT_BYTES + 1);
    let long = sign_message(&priv_node, &long);
    assert_eq!(verify_message(&long, &node, None), Err(Refusal::TooLarge));
}

#[test]
fn cursor_accepts_each_seq_once_per_kind() {
    let node = [1u8; 32];
    let mut c = Cursor::default();
    assert!(c.accept(&msg(&node, 1, Kind::Info, None)));
    assert!(!c.accept(&msg(&node, 1, Kind::Info, None)));
    assert!(c.accept(&msg(&node, 1, Kind::Alert, None)));
    assert!(!c.accept(&msg(&node, 0, Kind::Alert, None)));
    assert_eq!(c, Cursor { info: 1, alert: 1 });
}

#[test]
fn outbox_reads_since_cursor_prunes_and_inbox_is_rate_limited() {
    let priv_node = [1u8; 32];
    let node = pk(&priv_node);
    let mut o = Outbox::default();
    for seq in 1..=3 {
        let s = sign_message(&priv_node, &msg(&node, seq, Kind::Info, None));
        o.push(s, &node, None).unwrap();
    }
    let replay = sign_message(&priv_node, &msg(&node, 2, Kind::Info, None));
    assert_eq!(o.push(replay, &node, None), Err(Refusal::Replayed));
    assert_eq!(o.next_seq(Kind::Info), 4);
    assert_eq!(o.next_seq(Kind::Alert), 1);
    assert_eq!(o.since(1, 0, &[0; 32]).len(), 2);
    o.prune(1_002 + RETENTION_S);
    assert_eq!(o.sent.len(), 1);

    let mut inbox = Inbox::default();
    let user = [5u8; 32];
    for _ in 0..POSTS_PER_DAY {
        inbox.post(&user, "bonjour", 10).unwrap();
    }
    assert_eq!(inbox.post(&user, "encore", 11), Err(Refusal::RateLimited));
    assert!(inbox.post(&[6; 32], "autre", 11).is_ok());
    assert!(inbox.post(&user, "lendemain", 10 + DAY_S).is_ok());
    assert_eq!(
        inbox.post(&[6; 32], &"x".repeat(MAX_TEXT_BYTES + 1), 12),
        Err(Refusal::TooLarge)
    );
    inbox.prune(11 + RETENTION_S);
    assert_eq!(inbox.received.len(), 1);
}

#[test]
fn alert_entry_is_bound_to_the_announce_key_and_survives_republication() {
    let (priv_node, priv_announce) = ([1u8; 32], [2u8; 32]);
    let node = pk(&priv_node);
    let announce = pk(&priv_announce);
    let alert = sign_message(&priv_announce, &msg(&node, 1, Kind::Alert, None));
    let env = alert_entry_envelope(&priv_announce, &alert, 1_000);
    let (k, a) = open_alert_entry(&env, 2_000).unwrap();
    assert_eq!((k, &a), (announce, &alert));
    let no_vdf = |_: &[u8; 33], _: &s3m_core::vdf::VdfProof| Ok(false);
    let key = alert_dht_key(&announce);
    assert!(accept_record(&key, &env, None, 2_000, &no_vdf).is_ok());
    // Même enveloppe republiée : acceptée ; autre clé de recherche : refusée.
    assert!(accept_record(&key, &env, Some(&env), 3_000, &no_vdf).is_ok());
    assert!(accept_record(&alert_dht_key(&node), &env, None, 2_000, &no_vdf).is_err());
    // Expiration après 6 mois.
    assert!(open_alert_entry(&env, 1_001 + 15_552_000).is_err());
}

#[test]
fn messages_requests_and_response_roundtrip() {
    for body in [
        Body::ReadMessages {
            since_info: 4,
            since_alert: 1,
        },
        Body::PostMessage {
            text: "Plus de quota ?".into(),
        },
    ] {
        let r = Request {
            credential: None,
            body,
        };
        assert_eq!(decode_request(&encode_request(&r)).unwrap(), r);
    }
    let s = sign_message(&[1; 32], &msg(&pk(&[1; 32]), 1, Kind::Info, None));
    for node_name in [None, Some("Cheval".to_string())] {
        let r = Response::Messages {
            messages: vec![s.clone(), s.clone()],
            node_name,
        };
        assert_eq!(decode_response(&encode_response(&r)).unwrap(), r);
    }
    // Nom vide ou à nettoyer : rendu nettoyé, absent s'il est vide.
    let r = Response::Messages {
        messages: vec![],
        node_name: Some("  ".into()),
    };
    assert_eq!(
        decode_response(&encode_response(&r)).unwrap(),
        Response::Messages {
            messages: vec![],
            node_name: None
        }
    );
}

/// Message à un seul Utilisateur et remplacement de clé d'annonce
/// (`protocols.canal-noeud`) : champs signés, réservés aux `Info`, et
/// remise filtrée par destinataire.
#[test]
fn addressed_info_reaches_only_its_recipient_and_alerts_cannot_carry_it() {
    let priv_node = [1u8; 32];
    let node = pk(&priv_node);
    let (alice, bob) = ([0xa1; 32], [0xb2; 32]);
    let mut to_alice = msg(&node, 1, Kind::Info, None);
    to_alice.recipient = Some(alice);
    let mut replace = msg(&node, 2, Kind::Info, None);
    replace.announce_replacement = Some([0xcc; 32]);
    let s = sign_message(&priv_node, &to_alice);
    let back = verify_message(&s, &node, None).unwrap();
    assert_eq!(back.recipient, Some(alice));
    assert_eq!(
        verify_message(&sign_message(&priv_node, &replace), &node, None)
            .unwrap()
            .announce_replacement,
        Some([0xcc; 32])
    );
    // Destinataire signé : le changer invalide la signature.
    let mut forged = to_alice.clone();
    forged.recipient = Some(bob);
    let tampered = Signed {
        message: encode_message(&forged),
        signature: s.signature.clone(),
    };
    assert!(verify_message(&tampered, &node, None).is_err());
    // Une alerte ne porte ni destinataire ni remplacement.
    let priv_announce = [2u8; 32];
    let mut bad = msg(&node, 1, Kind::Alert, None);
    bad.recipient = Some(alice);
    assert!(verify_message(
        &sign_message(&priv_announce, &bad),
        &node,
        Some(&pk(&priv_announce))
    )
    .is_err());
    // Remise : Alice voit le sien et le message général, Bob seulement ce dernier.
    let mut o = Outbox::default();
    o.push(s, &node, None).unwrap();
    o.push(sign_message(&priv_node, &replace), &node, None)
        .unwrap();
    assert_eq!(o.since(0, 0, &alice).len(), 2);
    assert_eq!(o.since(0, 0, &bob).len(), 1);
}
