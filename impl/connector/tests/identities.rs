//! Plusieurs identités (`deploiement.packaging#plusieurs-identites`) :
//! rangement, ajout, retrait, état d'ensemble, dossier synchronisé distinct.

use s3m_connector::daemon::{folder_path, identity_number, Config, TrayState};
use s3m_connector::identities::*;

fn app(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("p2p-ident-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn identities_are_listed_added_and_set_aside() {
    let a = app("list");
    assert_eq!(list(&a), vec![(1, a.clone())]);
    let (n, d2) = next_dir(&a).unwrap();
    assert_eq!(n, 2);
    // Assistant pas terminé : pas listée, numéro réutilisé.
    assert_eq!(list(&a).len(), 1);
    assert_eq!(next_dir(&a).unwrap().0, 2);
    std::fs::write(d2.join("connector.json"), "{}").unwrap();
    let (n3, d3) = next_dir(&a).unwrap();
    assert_eq!(n3, 3);
    std::fs::write(d3.join("connector.json"), "{}").unwrap();
    assert_eq!(
        list(&a),
        vec![(1, a.clone()), (2, d2.clone()), (3, d3.clone())]
    );
    // Retrait : renommé, jamais effacé ; l'origine ne se retire pas.
    let to = set_aside(&a, &d2, 77).unwrap();
    assert!(to.ends_with("2.retiree-77") && to.join("connector.json").exists());
    assert_eq!(list(&a), vec![(1, a.clone()), (3, d3)]);
    assert!(set_aside(&a, &a, 1).is_err());
    assert_eq!(next_dir(&a).unwrap().0, 2);
}

#[test]
fn icon_follows_the_worst_identity() {
    use TrayState::*;
    assert_eq!(worst(&[Ok, Syncing]), Syncing);
    assert_eq!(worst(&[Ok, Offline, Paused]), Offline);
    assert_eq!(worst(&[Error, Offline]), Error);
    assert_eq!(worst(&[]), Starting);
}

#[test]
fn each_identity_gets_its_own_synced_folder() {
    let a = app("folder");
    let cfg = |p: std::path::PathBuf| {
        let mut c: Config = serde_json::from_value(serde_json::json!({
            "seed_file": "user.seed", "data_dir": "data",
            "node": { "addr": "/ip4/127.0.0.1/tcp/1", "node_id": "00", "salt": "00" }
        }))
        .unwrap();
        c.source = Some(p);
        c
    };
    let first = cfg(a.join("connector.json"));
    let second = cfg(a.join("identites").join("2").join("connector.json"));
    assert_eq!(identity_number(first.source.as_ref().unwrap()), None);
    assert_eq!(identity_number(second.source.as_ref().unwrap()), Some(2));
    assert!(folder_path(&first).ends_with("S3m"));
    assert!(folder_path(&second).ends_with("S3m 2"));
}
