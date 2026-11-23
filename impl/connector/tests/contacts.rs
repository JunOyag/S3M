//! Contacts : pseudo à la place de l'identifiant (partages, affichage).

use s3m_connector::contacts::Contacts;

const A: &str = "aa00000000000000000000000000000000000000000000000000000000000001";
const B: &str = "bb00000000000000000000000000000000000000000000000000000000000002";

#[test]
fn contacts_are_added_edited_resolved_and_removed() {
    let mut c = Contacts::default();
    c.upsert(None, "Alice", A).unwrap();
    c.upsert(None, "", &B.to_uppercase()).unwrap();
    // Unicité : identifiant, et pseudo (sans casse).
    assert!(c.upsert(None, "Autre", A).is_err());
    assert!(c.upsert(None, "alice", "cc".repeat(32).as_str()).is_err());
    assert!(c.upsert(None, "x", "pas un identifiant").is_err());
    // Destinataire : pseudo (sans casse), identifiant, vide.
    assert_eq!(
        c.resolve("ALICE").unwrap().map(hex::encode).as_deref(),
        Some(A)
    );
    assert_eq!(c.resolve(B).unwrap().map(hex::encode).as_deref(), Some(B));
    assert_eq!(c.resolve("  ").unwrap(), None);
    assert!(c.resolve("Inconnu").is_err());
    // Affichage : pseudo s'il existe, sinon empreinte.
    assert_eq!(c.display(A), "Alice");
    assert_ne!(c.display(B), "");
    assert_ne!(c.display(B), B);
    assert_eq!(c.pseudos(), vec!["Alice".to_string()]);
    // Modification : pseudo et identifiant ; son propre pseudo reste permis.
    c.upsert(Some(A), "Alice", A).unwrap();
    c.upsert(Some(B), "Bob", B).unwrap();
    assert_eq!(c.display(B), "Bob");
    let n = "dd".repeat(32);
    c.upsert(Some(B), "Bob", &n).unwrap();
    assert_eq!(c.pseudo_of(&n).as_deref(), Some("Bob"));
    assert!(c.pseudo_of(B).is_none());
    // Suppression.
    assert!(c.remove(&n));
    assert!(!c.remove(&n));
    assert_eq!(c.list.len(), 1);
    // Import : nouveaux ajoutés, présents gardés, pseudo pris abandonné.
    let export = serde_json::to_string(&c).unwrap();
    let mut other = Contacts::parse(&export).unwrap();
    other.upsert(None, "Alice", &"ee".repeat(32)).unwrap_err();
    other.upsert(None, "Eve", &"ee".repeat(32)).unwrap();
    let mut clash = Contacts::default();
    clash.upsert(None, "Eve", &"ff".repeat(32)).unwrap();
    let (added, skipped) = clash.merge(&other);
    assert_eq!(
        (added, skipped),
        (2, 0),
        "Alice ajoutée, Eve (pseudo pris) sans pseudo"
    );
    assert_eq!(clash.pseudo_of(&"ee".repeat(32)), None);
    assert_eq!(clash.pseudo_of(A).as_deref(), Some("Alice"));
    assert_eq!(clash.merge(&other), (0, 2), "déjà présents");
    assert!(Contacts::parse("n'importe quoi").is_err());
    let list = serde_json::to_string(&c.list).unwrap();
    assert_eq!(Contacts::parse(&list).unwrap(), c);

    // Conservation.
    let dir = std::env::temp_dir().join(format!("p2p-contacts-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    c.save(&dir).unwrap();
    assert_eq!(Contacts::load(&dir), c);
    let _ = std::fs::remove_dir_all(&dir);
}
