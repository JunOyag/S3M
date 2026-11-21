//! Tests de `protocols.canal-noeud`, côté Nœud.

use s3m_core::k_attach::derive_k_attach_as_user;
use s3m_node::channel::*;
use s3m_node::exchange::*;
use s3m_protocol::exchange::*;
use s3m_protocol::message::{open_alert_entry, verify_message, Kind, POSTS_PER_DAY};

const NODE: [u8; 32] = [0x10; 32];
const USER: [u8; 32] = [0x40; 32];
const SALT: [u8; 16] = [7; 16];
const NOW: u64 = 1_000_000;

fn pk(s: &[u8; 32]) -> Id {
    ed25519_dalek::SigningKey::from_bytes(s)
        .verifying_key()
        .to_bytes()
}

fn user_req(body: Body) -> Request {
    let k = derive_k_attach_as_user(&USER, &pk(&NODE), &SALT).unwrap();
    Request {
        credential: Some(Credential::User {
            user_id: pk(&USER).to_vec(),
            proof: connector_proof(&k, b"c", b"n").to_vec(),
        }),
        body,
    }
}

#[test]
fn announce_phrase_roundtrips_and_only_it_signs_alerts() {
    let (k, phrase) = new_announce_key();
    assert_eq!(phrase.split_whitespace().count(), 24);
    assert_eq!(announce_from_phrase(&phrase.to_uppercase()).unwrap(), k);
    assert!(announce_from_phrase("abandon abandon").is_err());

    let mut c = Channel::default();
    let phrase = c.create_announce().unwrap();
    assert!(c.create_announce().is_err());
    let k = announce_from_phrase(&phrase).unwrap();
    let node = pk(&NODE);
    assert!(c
        .post_alert(&node, &[9; 32], "compromis", None, NOW)
        .is_err());
    assert!(c
        .post_alert(&node, &k, "compromis", Some(node), NOW)
        .is_err());
    assert_eq!(
        c.post_alert(&node, &k, "compromis", Some([3; 32]), NOW),
        Ok(1)
    );
    let (key, env) = c.alert_due(NOW).unwrap();
    let (announce, alert) = open_alert_entry(&env, NOW).unwrap();
    assert_eq!(Some(announce), c.announce);
    assert_eq!(key, s3m_protocol::dht::alert_dht_key(&announce));
    let m = verify_message(&alert, &node, Some(&announce)).unwrap();
    assert_eq!((m.kind, m.successor), (Kind::Alert, Some([3; 32])));
    // Republication de la même enveloppe tous les 30 jours.
    c.alert_published_at = NOW;
    assert!(c.alert_due(NOW + 1).is_none());
    assert_eq!(c.alert_due(NOW + 2_592_000).map(|x| x.1), Some(env));
}

#[test]
fn attached_user_reads_node_messages_and_posts_within_the_daily_limit() {
    let mut s = NodeService::new(NODE);
    s.users.insert(
        pk(&USER),
        UserAccount {
            salt: SALT.to_vec(),
            quota_bytes: 1 << 20,
            used_bytes: 0,
            root: [0; 32],
        },
    );
    assert_eq!(
        s.channel.post_info(&NODE, "maintenance dimanche", NOW),
        Ok(1)
    );
    assert!(s.channel.post_info(&NODE, "  ", NOW).is_err());
    let call = |s: &mut NodeService, body: Body| s.handle(b"c", None, b"n", user_req(body), NOW);
    let read = Body::ReadMessages {
        since_info: 0,
        since_alert: 0,
    };
    s.name = Some("Cheval".into());
    let Response::Messages {
        messages: list,
        node_name,
    } = call(&mut s, read)
    else {
        panic!("messages attendus")
    };
    assert_eq!(list.len(), 1);
    assert_eq!(node_name.as_deref(), Some("Cheval"));
    assert_eq!(
        verify_message(&list[0], &pk(&NODE), None).unwrap().text,
        "maintenance dimanche"
    );
    let none = Body::ReadMessages {
        since_info: 1,
        since_alert: 0,
    };
    assert_eq!(
        call(&mut s, none),
        Response::Messages {
            messages: vec![],
            node_name: Some("Cheval".into())
        }
    );
    for _ in 0..POSTS_PER_DAY {
        assert_eq!(
            call(
                &mut s,
                Body::PostMessage {
                    text: "plus de quota ?".into()
                }
            ),
            Response::Ack { freed: 0 }
        );
    }
    assert_eq!(
        call(
            &mut s,
            Body::PostMessage {
                text: "encore".into()
            }
        ),
        Response::Failure(Refusal::RateLimited)
    );
    assert_eq!(s.channel.inbox.received[0].user_id, pk(&USER));
    // Sans identifiant valide : refusé.
    let anon = Request {
        credential: None,
        body: Body::PostMessage { text: "x".into() },
    };
    assert_eq!(
        s.handle(b"c", None, b"n", anon, NOW),
        Response::Failure(Refusal::Unauthorized)
    );
}

#[test]
fn user_messages_take_4_kib_of_quota_until_pruned_or_deleted() {
    use s3m_protocol::message::{MESSAGE_COST_BYTES, RETENTION_S};
    let mut s = NodeService::new(NODE);
    s.users.insert(
        pk(&USER),
        UserAccount {
            salt: SALT.to_vec(),
            quota_bytes: 2 * MESSAGE_COST_BYTES + 10,
            used_bytes: 0,
            root: [0; 32],
        },
    );
    let post = |s: &mut NodeService, now: u64| {
        s.handle(
            b"c",
            None,
            b"n",
            user_req(Body::PostMessage { text: "a".into() }),
            now,
        )
    };
    let used = |s: &NodeService| s.users[&pk(&USER)].used_bytes;
    assert_eq!(post(&mut s, NOW), Response::Ack { freed: 0 });
    assert_eq!(post(&mut s, NOW + 1), Response::Ack { freed: 0 });
    assert_eq!(used(&s), 2 * MESSAGE_COST_BYTES);
    // Quota plein : refusé, rien n'est conservé.
    assert_eq!(
        post(&mut s, NOW + 2),
        Response::Failure(Refusal::QuotaExceeded)
    );
    assert_eq!(s.channel.inbox.received.len(), 2);
    // Suppression par l'opérateur : quota rendu.
    assert!(!s.delete_user_message(&pk(&USER), NOW + 5));
    assert!(s.delete_user_message(&pk(&USER), NOW));
    assert_eq!(used(&s), MESSAGE_COST_BYTES);
    // Expiration : quota rendu.
    s.prune_channel(NOW + 1 + RETENTION_S);
    assert_eq!(used(&s), 0);
    assert!(s.channel.inbox.received.is_empty());
}
