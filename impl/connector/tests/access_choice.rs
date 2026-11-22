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
