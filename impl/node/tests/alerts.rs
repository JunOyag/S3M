//! Alertes hors tableau de bord (`deploiement.packaging#alertes`).

use std::collections::BTreeMap;
use std::io::{Read, Write};

use s3m_node::alerts::*;

fn a(k: &str) -> Alert {
    (k.into(), format!("titre {k}"), format!("texte {k}"))
}

#[test]
fn an_alert_is_sent_when_it_appears_and_again_if_it_comes_back() {
    let mut sent = BTreeMap::new();
    assert_eq!(new_alerts(&[a("disque")], &mut sent, 1).len(), 1);
    assert!(new_alerts(&[a("disque")], &mut sent, 2).is_empty(), "déjà envoyée");
    assert_eq!(new_alerts(&[a("disque"), a("horloge")], &mut sent, 3), vec![a("horloge")]);
    assert!(new_alerts(&[], &mut sent, 4).is_empty());
    assert_eq!(new_alerts(&[a("disque")], &mut sent, 5).len(), 1, "revenue");
}

#[test]
fn the_webhook_receives_the_alert_as_json() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut buf = vec![0u8; 4096];
        let mut got = Vec::new();
        loop {
            let n = s.read(&mut buf).unwrap();
            got.extend_from_slice(&buf[..n]);
            let text = String::from_utf8_lossy(&got);
            if let Some(i) = text.find("\r\n\r\n") {
                let len: usize = text
                    .lines()
                    .find_map(|l| l.to_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap()))
                    .unwrap_or(0);
                if got.len() >= i + 4 + len {
                    break;
                }
            }
        }
        s.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n").unwrap();
        String::from_utf8(got).unwrap()
    });
    let cfg = AlertConfig {
        popup: false,
        webhook: Some(format!("http://127.0.0.1:{port}/hook")),
        ..Default::default()
    };
    assert!(dispatch(&cfg, "nœud-1", "Volume 3 introuvable", "Rebranchez le disque").is_empty());
    let req = server.join().unwrap();
    assert!(req.starts_with("POST /hook"), "{req}");
    let body: serde_json::Value = serde_json::from_str(req.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!(body["alerte"], "Volume 3 introuvable");
    assert_eq!(body["nœud"], "nœud-1");
}

#[test]
fn a_bad_smtp_configuration_is_reported() {
    let cfg = AlertConfig {
        popup: false,
        smtp_server: Some("127.0.0.1:1".into()),
        email_to: Some("pas-une-adresse".into()),
        smtp_user: Some("moi@exemple.fr".into()),
        ..Default::default()
    };
    let e = dispatch(&cfg, "n", "t", "x");
    assert_eq!(e.len(), 1);
    assert!(e[0].starts_with("courriel"), "{e:?}");
}
