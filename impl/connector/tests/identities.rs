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
    // Premier lancement : l'origine seule, même non configurée (assistant).
    assert_eq!(list(&a), vec![(1, a.clone())]);
    std::fs::write(a.join("connector.json"), "{}").unwrap();
    std::fs::write(a.join("user.seed"), "mots").unwrap();
    std::fs::create_dir_all(a.join("logs")).unwrap();
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
    // Retrait d'une identité ajoutée : renommée, jamais effacée.
    let to = set_aside(&a, &d2, 77).unwrap();
    assert!(to.ends_with("2.retiree-77") && to.join("connector.json").exists());
    assert_eq!(list(&a), vec![(1, a.clone()), (3, d3.clone())]);
    assert_eq!(next_dir(&a).unwrap().0, 2);
    // Retrait de l'origine (il en reste une autre) : ses fichiers sont mis de
    // côté, ceux de l'application restent, elle n'est plus lancée.
    let to = set_aside(&a, &a, 78).unwrap();
    assert!(
        to.ends_with("1.retiree-78")
            && to.join("connector.json").exists()
            && to.join("user.seed").exists()
    );
    assert!(a.join("logs").exists() && !a.join("connector.json").exists());
    assert_eq!(list(&a), vec![(3, d3.clone())]);
    // Changement de Nœud : configuration mise de côté, phrase gardée —
    // l'identité reste lancée (assistant) et son dossier n'est pas repris.
    std::fs::write(d3.join("user.seed"), "mots").unwrap();
    std::fs::remove_file(d3.join("connector.json")).unwrap();
    assert_eq!(list(&a), vec![(3, d3.clone())]);
    let (n4, _) = next_dir(&a).unwrap();
    assert_ne!(n4, 3);
    let back = app("retour");
    std::fs::write(back.join("user.seed"), "mots").unwrap();
    let (_, other) = next_dir(&back).unwrap();
    std::fs::write(other.join("connector.json"), "{}").unwrap();
    assert_eq!(
        list(&back)[0],
        (1, back.clone()),
        "origine sans configuration mais avec sa phrase"
    );
    // Dernière identité : l'origine ne se retire pas seule.
    let solo = app("solo");
    std::fs::write(solo.join("connector.json"), "{}").unwrap();
    assert!(set_aside(&solo, &solo, 1).is_err());
}

#[test]
fn archived_identities_are_restored_or_purged() {
    let a = app("archive");
    std::fs::write(a.join("connector.json"), "{}").unwrap();
    let (_, d2) = next_dir(&a).unwrap();
    std::fs::write(d2.join("connector.json"), "{}").unwrap();
    std::fs::create_dir_all(d2.join("data")).unwrap();
    std::fs::write(
        d2.join("data").join("names.json"),
        r#"{"pseudo":"Toto","node_label":""}"#,
    )
    .unwrap();
    let (_, d3) = next_dir(&a).unwrap();
    std::fs::write(d3.join("connector.json"), "{}").unwrap();
    // 2023-11-14 22:13:20 UTC, puis un peu plus tard.
    set_aside(&a, &d2, 1_700_000_000).unwrap();
    set_aside(&a, &d3, 1_700_000_100).unwrap();
    let ar = archived(&a);
    assert_eq!(ar.len(), 2);
    assert_eq!(ar[0].num, 3, "la plus récente d'abord");
    assert_eq!(ar[1].label(), "Toto — retirée le 14/11/2023");
    assert_eq!(ar[0].label(), "Identité 3 — retirée le 14/11/2023");
    // Restauration : premier numéro libre ; dossier vide d'assistant réutilisé.
    std::fs::create_dir_all(a.join("identites").join("2")).unwrap();
    let (n, to) = restore(&a, &ar[1].dir).unwrap();
    assert_eq!(n, 2);
    assert!(to.join("connector.json").exists());
    assert!(list(&a).iter().any(|(k, _)| *k == 2));
    // Suppression définitive ; rien hors des archives.
    purge(&a, &ar[0].dir).unwrap();
    assert!(archived(&a).is_empty());
    assert!(purge(&a, &to).is_err());
    assert!(restore(&a, &a).is_err());
}

#[test]
fn icon_follows_the_worst_identity() {
    use TrayState::*;
    assert_eq!(worst(&[Ok, Syncing]), Syncing);
    assert_eq!(
        worst(&[Starting, Syncing]),
        Syncing,
        "le travail en attente passe avant le démarrage"
    );
    assert_eq!(needing_attention(&[Ok, Syncing, Offline]), 2);
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
