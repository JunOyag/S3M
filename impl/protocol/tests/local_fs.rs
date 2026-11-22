//! Explorateur de dossiers des tableaux de bord : contenu, création,
//! espace du disque.

use s3m_protocol::local_fs::*;
use serde_json::json;

#[test]
fn browse_lists_folders_creates_one_and_reports_space() {
    let base = std::env::temp_dir().join(format!("p2p-fs-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("b")).unwrap();
    std::fs::create_dir_all(base.join("A")).unwrap();
    std::fs::create_dir_all(base.join(".cache")).unwrap();
    std::fs::write(base.join("fichier.txt"), b"x").unwrap();
    let r = browse(&json!({ "chemin": base.display().to_string() })).unwrap();
    let d = &r["données"];
    assert_eq!(
        d["dossiers"],
        json!(["A", "b"]),
        "dossiers seuls, cachés exclus, triés"
    );
    assert!(d["parent"].is_string());
    assert!(!d["racines"].as_array().unwrap().is_empty());
    let e = &d["espace"];
    assert!(e["total (octets)"].as_u64().unwrap() > 0);
    assert!(e["disponible (octets)"].as_u64().unwrap() <= e["total (octets)"].as_u64().unwrap());
    // Dossier pas encore créé : espace de son disque.
    let later = base.join("pas").join("encore");
    let s = browse(&json!({ "chemin": later.display().to_string(), "espace seul": true })).unwrap();
    assert!(s["données"]["espace"]["total (octets)"].as_u64().unwrap() > 0);
    assert!(browse(&json!({ "chemin": later.display().to_string() })).is_err());
    let made = mkdir(&json!({ "chemin": base.display().to_string(), "nom": "Nouveau" })).unwrap();
    assert!(base.join("Nouveau").is_dir());
    assert!(made["données"]["chemin"]
        .as_str()
        .unwrap()
        .ends_with("Nouveau"));
    for bad in ["", "..", "a/b", r"a\b", "c:"] {
        assert!(
            mkdir(&json!({ "chemin": base.display().to_string(), "nom": bad })).is_err(),
            "{bad}"
        );
    }
    let _ = std::fs::remove_dir_all(&base);
}
