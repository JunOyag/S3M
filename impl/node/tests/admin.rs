//! `deploiement.appairage-admin` : règles d'authentification du canal
//! d'administration (appairage SPAKE2, TOTP, sessions, essais limités) et
//! assistant de premier lancement.

use std::sync::Arc;
use std::time::{Duration, Instant};

use libp2p::PeerId;
use s3m_node::admin::{hotp, Auth, Mode, SecretFn, TOTP_STEP};
use s3m_node::local_http::{ActionFn, StatusFn};
use s3m_node::setup::parse_recovery;
use s3m_protocol::admin::{
    confirm_mac, pake_finish, pake_start, AdminRequest, AdminResponse, Side,
};
use serde_json::json;

fn fns() -> (StatusFn, ActionFn) {
    (
        Arc::new(|| json!({ "titre": "essai", "carte": true })),
        Arc::new(|n, _| Ok(json!({ "fait": n }))),
    )
}

fn call(token: &str, op: &str, name: Option<&str>) -> AdminRequest {
    AdminRequest::Call {
        token: token.into(),
        op: op.into(),
        name: name.map(Into::into),
        body: json!({}),
    }
}

#[test]
fn hotp_matches_rfc6238_sha1_vectors() {
    let secret = b"12345678901234567890";
    assert_eq!(hotp(secret, 59 / 30, 8), 94287082);
    assert_eq!(hotp(secret, 1111111109 / 30, 8), 7081804);
    assert_eq!(hotp(secret, 2000000000 / 30, 8), 69279037);
}

fn pair(auth: &mut Auth, node: PeerId, client: PeerId, code: &str, now: Instant) -> AdminResponse {
    let (st, fns) = fns();
    let (s, msg) = pake_start(code);
    let reply = match auth.handle(
        client,
        AdminRequest::PakeStart {
            msg: hex::encode(msg),
        },
        now,
        0,
        &st,
        &fns,
    ) {
        AdminResponse::PakeReply { msg } => msg,
        other => return other,
    };
    let k = pake_finish(s, &hex::decode(reply).unwrap()).unwrap();
    let mac = confirm_mac(&k, Side::Client, &node.to_bytes(), &client.to_bytes());
    let r = auth.handle(
        client,
        AdminRequest::PakeConfirm {
            mac: hex::encode(mac),
        },
        now,
        0,
        &st,
        &fns,
    );
    if let AdminResponse::Session { mac: Some(m), .. } = &r {
        let want = confirm_mac(&k, Side::Node, &node.to_bytes(), &client.to_bytes());
        assert_eq!(
            hex::decode(m).unwrap(),
            want,
            "le Connecteur authentifie le Nœud"
        );
    }
    r
}

#[test]
fn pairing_opens_a_session_only_with_the_right_code_and_limits_attempts() {
    let (node, client, other) = (PeerId::random(), PeerId::random(), PeerId::random());
    let mut auth = Auth::new(
        Mode::Setup {
            code: "ABCD-EFGH".into(),
        },
        node,
    );
    let (st, act) = fns();
    let now = Instant::now();
    let r = auth.handle(client, AdminRequest::Hello {}, now, 0, &st, &act);
    assert!(matches!(r, AdminResponse::Hello { ref mode, .. } if mode == "setup"));
    // Mauvais code : refus, puis blocage après 5 échecs.
    for _ in 0..5 {
        assert!(matches!(
            pair(&mut auth, node, client, "ABCD-EFGX", now),
            AdminResponse::Error(_)
        ));
    }
    assert!(
        matches!(
            pair(&mut auth, node, client, "abcd efgh", now),
            AdminResponse::Error(_)
        ),
        "bloqué"
    );
    let later = now + Duration::from_secs(61);
    let AdminResponse::Session { token, .. } = pair(&mut auth, node, client, "abcd efgh", later)
    else {
        panic!("session attendue")
    };
    // La session est liée au pair ; la carte n'est pas exposée.
    let r = auth.handle(other, call(&token, "status", None), later, 0, &st, &act);
    assert!(matches!(r, AdminResponse::Error(_)));
    let r = auth.handle(client, call(&token, "status", None), later, 0, &st, &act);
    let AdminResponse::Result(v) = r else {
        panic!()
    };
    assert!(v.get("carte").is_none());
    // Le TOTP n'est pas accepté sous identité temporaire.
    let r = auth.handle(
        client,
        AdminRequest::Login {
            totp: "000000".into(),
        },
        later,
        0,
        &st,
        &act,
    );
    assert!(matches!(r, AdminResponse::Error(_)));
    // Expiration après 30 min d'inactivité.
    let r = auth.handle(
        client,
        call(&token, "status", None),
        later + Duration::from_secs(1801),
        0,
        &st,
        &act,
    );
    assert!(matches!(r, AdminResponse::Error(_)));
}

#[test]
fn totp_login_refuses_replay_and_local_only_actions_and_follows_the_serial() {
    let (node, client) = (PeerId::random(), PeerId::random());
    let secret = Arc::new(std::sync::Mutex::new([3u8; 20]));
    let s2 = secret.clone();
    let f: SecretFn = Arc::new(move || Some(*s2.lock().unwrap()));
    let mut auth = Auth::new(Mode::Node { secret: f }, node);
    let (st, act) = fns();
    let (now, unix) = (Instant::now(), 1_800_000_000u64);
    let code = format!("{:06}", hotp(&[3u8; 20], unix / TOTP_STEP, 6));
    let r = auth.handle(
        client,
        AdminRequest::PakeStart { msg: "00".into() },
        now,
        unix,
        &st,
        &act,
    );
    assert!(
        matches!(r, AdminResponse::Error(_)),
        "pas d'appairage une fois configuré"
    );
    let AdminResponse::Session { token, mac: None } = auth.handle(
        client,
        AdminRequest::Login { totp: code.clone() },
        now,
        unix,
        &st,
        &act,
    ) else {
        panic!("session attendue")
    };
    // Même pas réutilisé : refusé.
    let r = auth.handle(
        client,
        AdminRequest::Login { totp: code },
        now,
        unix,
        &st,
        &act,
    );
    assert!(matches!(r, AdminResponse::Error(_)));
    let r = auth.handle(
        client,
        call(&token, "action", Some("set_quota")),
        now,
        unix,
        &st,
        &act,
    );
    assert!(matches!(r, AdminResponse::Result(_)));
    let r = auth.handle(
        client,
        call(&token, "action", Some("show_totp")),
        now,
        unix,
        &st,
        &act,
    );
    assert!(
        matches!(r, AdminResponse::Error(_)),
        "réservée au dashboard local"
    );
    // Régénération (série + 1) : la session tombe.
    *secret.lock().unwrap() = [4u8; 20];
    let r = auth.handle(client, call(&token, "status", None), now, unix, &st, &act);
    assert!(matches!(r, AdminResponse::Error(_)));
}

#[test]
fn recovery_input_accepts_the_words_only() {
    let words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    assert_eq!(
        parse_recovery(&format!("  {}  ", words.to_uppercase())).unwrap(),
        words
    );
    assert!(
        parse_recovery("S3M1:N:AAAA:AAAAAAA").is_err(),
        "plus de code S3M1"
    );
    assert!(parse_recovery("abandon abandon").is_err());
}
