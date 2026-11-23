//! Page « Explorateur » du dashboard Connecteur : arborescence de l'espace,
//! création de dossiers, envoi et téléchargement de fichiers par morceaux,
//! déplacement, suppression. Partage et « garder sur cet appareil »
//! réutilisent les actions des pages Partages et Fichiers.

use std::sync::Arc;

use serde_json::{json, Value};

use crate::daemon::Shared;
use crate::drive::SHARED_DIR;

/// Taille d'un morceau envoyé ou lu (octets) : sous la limite des requêtes
/// du dashboard une fois encodé en hexadécimal.
pub const CHUNK: usize = 512 * 1024;

fn text(v: &Value, k: &str) -> String {
    v.get(k)
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim()
        .to_string()
}

/// Chemin de l'espace normalisé (`/a/b`).
fn norm(p: &str) -> String {
    let parts: Vec<&str> = p.split('/').filter(|x| !x.is_empty()).collect();
    format!("/{}", parts.join("/"))
}

fn writable(p: &str) -> Result<(), String> {
    if p == "/" {
        return Err("la racine ne peut pas être modifiée".into());
    }
    if p == SHARED_DIR || p.starts_with(&format!("{SHARED_DIR}/")) {
        return Err("« Partagés avec moi » est en lecture seule".into());
    }
    Ok(())
}

/// Modification enregistrée : synchronisation avec le Nœud.
fn changed(sh: &Arc<Shared>, path: &str, size: u64) {
    sh.scheduler
        .lock()
        .unwrap()
        .on_write(path, size, (sh.clock)());
    crate::daemon::sync_now(sh);
}

/// Supprime un élément, dossier compris avec tout son contenu.
fn remove_all(d: &mut crate::drive::Drive, p: &str) -> Result<(), String> {
    let m = d.stat(p).map_err(|e| e.to_string())?.ok_or("introuvable")?;
    if m.is_dir {
        for (n, _) in d.list(p).map_err(|e| e.to_string())? {
            remove_all(d, &format!("{}/{n}", p.trim_end_matches('/')))?;
        }
    }
    d.remove(p).map_err(|e| e.to_string())
}

/// Actions de l'explorateur ; `None` si le nom n'en est pas une.
pub fn action(sh: &Arc<Shared>, name: &str, v: &Value) -> Option<Result<Value, String>> {
    if !name.starts_with("explorer_") {
        return None;
    }
    let Some(drive) = sh.drive.clone() else {
        return Some(Err("accès aux fichiers non configuré".into()));
    };
    Some((|| match name {
        "explorer_list" => {
            let p = norm(&text(v, "chemin"));
            let mut d = drive.lock().unwrap();
            let mut entries = d.list(&p).map_err(|e| e.to_string())?;
            drop(d);
            entries.sort_by(|a, b| {
                b.1.is_dir
                    .cmp(&a.1.is_dir)
                    .then(a.0.to_lowercase().cmp(&b.0.to_lowercase()))
            });
            let keep = sh.keep_offline.lock().unwrap().clone();
            let folder = crate::daemon::access_mode(&sh.config) == "dossier";
            let kept = |path: &str| {
                keep.iter().any(|k| {
                    let k = k.trim_end_matches('/');
                    path.eq_ignore_ascii_case(k)
                        || path
                            .to_lowercase()
                            .starts_with(&format!("{}/", k.to_lowercase()))
                })
            };
            let pseudos = sh.contacts.lock().unwrap().pseudos();
            Ok(json!({
                "chemin": p,
                "contacts": pseudos,
                "mode dossier": folder,
                "lecture seule": writable(&p).is_err() && p != "/",
                "entrées": entries.iter().map(|(n, m)| {
                    let full = format!("{}/{n}", p.trim_end_matches('/'));
                    json!({ "nom": n, "dossier": m.is_dir, "taille": m.size,
                            "modifié": m.modified_at, "gardé": folder && kept(&full),
                            "lecture seule": writable(&full).is_err() })
                }).collect::<Vec<_>>(),
            }))
        }
        "explorer_mkdir" => {
            let p = norm(&text(v, "chemin"));
            writable(&p)?;
            drive
                .lock()
                .unwrap()
                .create(&p, true)
                .map_err(|e| e.to_string())?;
            changed(sh, &p, 0);
            Ok(json!({ "ok": true, "message": format!("Dossier {p} créé") }))
        }
        "explorer_write" => {
            let p = norm(&text(v, "chemin"));
            writable(&p)?;
            let offset = v.get("offset").and_then(|x| x.as_u64()).unwrap_or(0);
            let data = hex::decode(text(v, "données")).map_err(|_| "données invalides")?;
            let last = v.get("fin").and_then(|x| x.as_bool()).unwrap_or(false);
            let mut d = drive.lock().unwrap();
            if offset == 0 {
                // Nouveau fichier, ou remplacement d'un fichier existant.
                match d.stat(&p).map_err(|e| e.to_string())? {
                    Some(m) if m.is_dir => return Err(format!("{p} est un dossier")),
                    Some(_) => d.set_size(&p, 0).map_err(|e| e.to_string())?,
                    None => d.create(&p, false).map_err(|e| e.to_string())?,
                }
            }
            if !data.is_empty() {
                d.write(&p, offset, &data).map_err(|e| e.to_string())?;
            }
            drop(d);
            let size = offset + data.len() as u64;
            if last {
                changed(sh, &p, size);
            }
            Ok(json!({ "ok": true, "taille": size }))
        }
        "explorer_read" => {
            let p = norm(&text(v, "chemin"));
            let offset = v.get("offset").and_then(|x| x.as_u64()).unwrap_or(0);
            let data = drive
                .lock()
                .unwrap()
                .read(&p, offset, CHUNK)
                .map_err(|e| e.to_string())?;
            Ok(json!({ "données": hex::encode(&data), "fin": data.len() < CHUNK }))
        }
        "explorer_move" => {
            let from = norm(&text(v, "de"));
            let to = norm(&text(v, "vers"));
            writable(&from)?;
            writable(&to)?;
            if to == from || to.starts_with(&format!("{from}/")) {
                return Err("un dossier ne peut pas être déplacé dans lui-même".into());
            }
            drive
                .lock()
                .unwrap()
                .rename(&from, &to, false)
                .map_err(|e| e.to_string())?;
            changed(sh, &to, 0);
            Ok(json!({ "ok": true, "message": format!("{from} → {to}") }))
        }
        "explorer_delete" => {
            let p = norm(&text(v, "chemin"));
            writable(&p)?;
            remove_all(&mut drive.lock().unwrap(), &p)?;
            changed(sh, &p, 0);
            Ok(json!({ "ok": true, "message": format!("{p} supprimé") }))
        }
        other => Err(format!("action inconnue : {other}")),
    })())
}
