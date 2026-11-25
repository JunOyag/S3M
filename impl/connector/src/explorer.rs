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

/// Version passée désignée par son hash (`protocols.historique-versions`).
fn version_root(sh: &Arc<Shared>, id: &str) -> Result<crate::access::Root, String> {
    let find = |h: &crate::daemon::HistoryView| {
        h.versions
            .iter()
            .find(|v| hex::encode(v.hash) == id)
            .map(|v| v.root.clone())
    };
    let cached = sh.history.lock().unwrap().as_ref().and_then(find);
    let found = match cached {
        Some(r) => Some(r),
        None => find(&crate::daemon::read_versions(sh)?),
    };
    found
        .ok_or("version introuvable (purgée ou expirée)")?
        .ok_or_else(|| "version illisible : descripteur absent".to_string())
}

/// Copie `src` de la version `root` vers l'espace courant (dossier compris).
fn restore_from(
    d: &mut crate::drive::Drive,
    root: &crate::access::Root,
    src: &str,
) -> Result<u64, String> {
    let m = d
        .stat_at(root, src)
        .map_err(|e| e.to_string())?
        .ok_or("introuvable dans cette version")?;
    if m.is_dir {
        if d.stat(src).map_err(|e| e.to_string())?.is_none() {
            d.create(src, true).map_err(|e| e.to_string())?;
        }
        let mut n = 0;
        for (name, _) in d.list_at(root, src).map_err(|e| e.to_string())? {
            n += restore_from(d, root, &format!("{}/{name}", src.trim_end_matches('/')))?;
        }
        return Ok(n);
    }
    let data = d
        .read_at(root, src, 0, usize::MAX)
        .map_err(|e| e.to_string())?;
    match d.stat(src).map_err(|e| e.to_string())? {
        Some(c) if c.is_dir => return Err(format!("{src} est devenu un dossier")),
        Some(_) => d.set_size(src, 0).map_err(|e| e.to_string())?,
        None => d.create(src, false).map_err(|e| e.to_string())?,
    }
    if !data.is_empty() {
        d.write(src, 0, &data).map_err(|e| e.to_string())?;
    }
    Ok(1)
}

/// Réécrit `p` (dossier compris) : ses blocs sont chiffrés de nouveau avec
/// la clé maîtresse courante (`securite.incidents-compromissions#rotation-user`).
fn reencrypt(d: &mut crate::drive::Drive, p: &str) -> Result<u64, String> {
    // Déjà sous la nouvelle clé : rien à faire.
    let mut budget = usize::MAX;
    if !d.uses_old_key(p, &mut budget) {
        return Ok(0);
    }
    let m = d.stat(p).map_err(|e| e.to_string())?.ok_or("introuvable")?;
    if m.is_dir {
        let mut n = 0;
        for (name, _) in d.list(p).map_err(|e| e.to_string())? {
            let c = format!("{}/{name}", p.trim_end_matches('/'));
            if writable(&c).is_ok() {
                n += reencrypt(d, &c)?;
            }
        }
        return Ok(n);
    }
    let data = d.read(p, 0, usize::MAX).map_err(|e| e.to_string())?;
    d.set_size(p, 0).map_err(|e| e.to_string())?;
    if !data.is_empty() {
        d.write(p, 0, &data).map_err(|e| e.to_string())?;
    }
    Ok(1)
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
        "explorer_list" if !text(v, "version").is_empty() => {
            let p = norm(&text(v, "chemin"));
            let root = version_root(sh, &text(v, "version"))?;
            let mut entries = drive
                .lock()
                .unwrap()
                .list_at(&root, &p)
                .map_err(|e| e.to_string())?;
            entries.sort_by(|a, b| {
                b.1.is_dir
                    .cmp(&a.1.is_dir)
                    .then(a.0.to_lowercase().cmp(&b.0.to_lowercase()))
            });
            Ok(json!({
                "chemin": p,
                "version": text(v, "version"),
                "lecture seule": true,
                "entrées": entries.iter().map(|(n, m)| json!({ "nom": n, "dossier": m.is_dir,
                    "taille": m.size, "modifié": m.modified_at, "lecture seule": true })).collect::<Vec<_>>(),
            }))
        }
        "explorer_versions" => {
            let p = norm(&text(v, "chemin"));
            let h = crate::daemon::read_versions(sh)?;
            let mut d = drive.lock().unwrap();
            let current = d.stat(&p).map_err(|e| e.to_string())?;
            let mut rows = Vec::new();
            for ver in &h.versions {
                let Some(root) = &ver.root else { continue };
                if let Ok(Some(m)) = d.stat_at(root, &p) {
                    rows.push(json!({ "version": hex::encode(ver.hash), "du": ver.valid_from,
                        "remplacée le": ver.replaced_at, "dossier": m.is_dir, "taille": m.size,
                        "modifié": m.modified_at }));
                }
            }
            Ok(json!({ "chemin": p, "actuelle": current.map(|m| json!({ "taille": m.size, "modifié": m.modified_at })),
                "versions": rows, "conservation (jours)": h.retention_s / 86_400 }))
        }
        "explorer_reencrypt" => {
            let p = norm(&text(v, "chemin"));
            if p != "/" {
                writable(&p)?;
            }
            let mut d = drive.lock().unwrap();
            if d.key_version() <= crate::drive::KEY_VERSION {
                return Err("aucun changement d'identité : rien à rechiffrer".into());
            }
            let n = reencrypt(&mut d, &p)?;
            drop(d);
            if n == 0 {
                return Ok(json!({ "ok": true, "message": "Déjà protégé par la nouvelle clé : rien à rechiffrer" }));
            }
            changed(sh, &p, 0);
            Ok(json!({ "ok": true, "message": format!("{n} fichier(s) rechiffré(s) avec la nouvelle clé (envoi en cours)") }))
        }
        "explorer_restore_all" => {
            let root = version_root(sh, &text(v, "version"))?;
            drive
                .lock()
                .unwrap()
                .restore_root(root)
                .map_err(|e| e.to_string())?;
            *sh.history.lock().unwrap() = None;
            Ok(json!({ "ok": true, "message": "Tout votre espace est revenu à cette version ; la version précédente reste dans l'historique." }))
        }
        "explorer_restore" => {
            let p = norm(&text(v, "chemin"));
            writable(&p)?;
            let root = version_root(sh, &text(v, "version"))?;
            let n = restore_from(&mut drive.lock().unwrap(), &root, &p)?;
            changed(sh, &p, 0);
            Ok(json!({ "ok": true, "message": format!("{p} restauré ({n} fichier(s))") }))
        }
        "explorer_list" => {
            let p = norm(&text(v, "chemin"));
            let mut d = drive.lock().unwrap();
            let listed = d.list(&p);
            drop(d);
            let mut entries = listed.map_err(|e| {
                if sh.health.lock().unwrap().files_missing {
                    crate::daemon::FILES_MISSING.to_string()
                } else {
                    e.to_string()
                }
            })?;
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
            // Trousseau des anciennes clés : jamais montré ni modifiable ici.
            if p == "/" {
                let hidden = crate::keychain::TREE_DIR.trim_start_matches('/');
                entries.retain(|(n, _)| n != hidden);
            }
            let reencrypt = drive.lock().unwrap().key_version() > crate::drive::KEY_VERSION;
            // Éléments encore protégés par l'ancienne clé (compromise).
            let old: Vec<bool> = if reencrypt {
                let mut d = drive.lock().unwrap();
                entries
                    .iter()
                    .map(|(n, _)| {
                        let mut budget = 2_000;
                        d.uses_old_key(&format!("{}/{n}", p.trim_end_matches('/')), &mut budget)
                    })
                    .collect()
            } else {
                vec![false; entries.len()]
            };
            Ok(json!({
                "chemin": p,
                "contacts": pseudos,
                "rechiffrer": reencrypt,
                "éléments à l'ancienne clé": old.iter().filter(|x| **x).count(),
                "mode dossier": folder,
                "lecture seule": writable(&p).is_err() && p != "/",
                "entrées": entries.iter().zip(&old).map(|((n, m), o)| {
                    let full = format!("{}/{n}", p.trim_end_matches('/'));
                    json!({ "nom": n, "dossier": m.is_dir, "taille": m.size,
                            "modifié": m.modified_at, "gardé": folder && kept(&full),
                            "ancienne clé": o,
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
            let version = text(v, "version");
            let data = if version.is_empty() {
                drive.lock().unwrap().read(&p, offset, CHUNK)
            } else {
                let root = version_root(sh, &version)?;
                drive.lock().unwrap().read_at(&root, &p, offset, CHUNK)
            }
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
