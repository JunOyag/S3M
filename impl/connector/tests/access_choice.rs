//! Accès aux fichiers : même formulaire dans l'assistant et dans le tableau
//! de bord (`protocols.acces-applicatif#mode-dossier`).

use s3m_connector::setup::{access_form, parse_access, AccessChoice};
use serde_json::json;

#[test]
fn access_choice_is_validated_and_the_form_fits_the_platform() {
    let dir = std::env::temp_dir();
    let folder = dir.join("S3m-essai").display().to_string();
    let c = parse_access(&json!({ "accès": "dossier", "dossier": folder })).unwrap();
    assert_eq!(c.access.as_deref(), Some("dossier"));
    assert!(c.mount.is_none());
    assert!(parse_access(&json!({ "accès": "dossier", "dossier": "relatif" })).is_err());
    assert!(parse_access(&json!({ "accès": "autre" })).is_err());
    let f = access_form(&AccessChoice::default(), &dir);
    assert_eq!(f["libellé"], "Appliquer");
    let fields = f["champs"].to_string();
    if cfg!(windows) {
        assert!(fields.contains("lettre") && !fields.contains("point de montage"));
    } else {
        assert!(fields.contains("point de montage") && !fields.contains("lettre"));
    }
    assert_eq!(f["visible_si"]["dossier"], json!(["accès", "dossier"]));
}

/// Le dossier proposé par défaut existe toujours, sinon le champ est vide.
#[test]
fn default_folder_is_never_a_missing_path() {
    let dir = std::env::temp_dir().join(format!("p2p-access-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let missing = AccessChoice {
        access: Some("dossier".into()),
        folder: Some(dir.join("absent")),
        mount: None,
    };
    assert_eq!(access_form(&missing, &dir)["valeurs"]["dossier"], "");
    let present = AccessChoice {
        folder: Some(dir.clone()),
        ..missing
    };
    assert_eq!(
        access_form(&present, &dir)["valeurs"]["dossier"],
        dir.display().to_string()
    );
}

#[test]
fn start_form_takes_everything_typed_in_one_click() {
    let dir = std::env::temp_dir();
    let f = s3m_connector::setup::start_form(&AccessChoice::default(), &dir);
    assert_eq!(f["nom"], "start");
    assert_eq!(f["libellé"], "Démarrer sous cette identité");
    let champs: Vec<&str> = f["champs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap())
        .collect();
    assert_eq!(champs[0], "adresse du nœud");
    assert!(champs.contains(&"accès") && champs.contains(&"dossier"));
    assert_eq!(f["valeurs"]["accès"], "dossier");
}
