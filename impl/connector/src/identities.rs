//! Plusieurs identités dans `S3m.exe` (`deploiement.packaging#plusieurs-identites`) :
//! rangement des dossiers d'identité, ajout, retrait, état d'ensemble.

use std::path::{Path, PathBuf};

use crate::daemon::TrayState;
use crate::setup::config_path;

/// Dossier des identités ajoutées.
pub fn identities_dir(app: &Path) -> PathBuf {
    app.join("identites")
}

/// Identités à lancer : l'identité d'origine (`app`, configurée ou non),
/// puis les identités ajoutées configurées, par numéro croissant.
pub fn list(app: &Path) -> Vec<(u32, PathBuf)> {
    let mut out = vec![(1, app.to_path_buf())];
    let mut added: Vec<(u32, PathBuf)> = std::fs::read_dir(identities_dir(app))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let n: u32 = e.file_name().to_str()?.parse().ok()?;
            let p = e.path();
            (n >= 2 && config_path(&p).exists()).then_some((n, p))
        })
        .collect();
    added.sort();
    out.extend(added);
    out
}

/// Dossier d'une nouvelle identité : premier numéro (à partir de 2) libre,
/// ou dont l'assistant n'a pas été terminé. Le dossier est créé.
pub fn next_dir(app: &Path) -> std::io::Result<(u32, PathBuf)> {
    let base = identities_dir(app);
    for n in 2u32.. {
        let p = base.join(n.to_string());
        if !config_path(&p).exists() {
            std::fs::create_dir_all(&p)?;
            return Ok((n, p));
        }
    }
    unreachable!()
}

/// Retrait d'une identité ajoutée : son dossier est renommé
/// `<n>.retiree-<horodatage>`, jamais effacé. L'identité d'origine ne se
/// retire pas.
pub fn set_aside(app: &Path, dir: &Path, stamp: u64) -> Result<PathBuf, String> {
    let base = identities_dir(app);
    if dir.parent() != Some(base.as_path()) {
        return Err("seule une identité ajoutée peut être retirée".into());
    }
    let name = dir
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| n.parse::<u32>().is_ok())
        .ok_or("dossier d'identité inattendu")?;
    let to = base.join(format!("{name}.retiree-{stamp}"));
    std::fs::rename(dir, &to).map_err(|e| e.to_string())?;
    Ok(to)
}

fn rank(s: TrayState) -> u8 {
    match s {
        TrayState::Ok => 0,
        TrayState::Syncing => 1,
        TrayState::Paused => 2,
        TrayState::Starting => 3,
        TrayState::Offline => 4,
        TrayState::Error => 5,
    }
}

/// État d'ensemble pour l'icône : celui de l'identité dans le pire état.
pub fn worst(states: &[TrayState]) -> TrayState {
    states
        .iter()
        .copied()
        .max_by_key(|s| rank(*s))
        .unwrap_or(TrayState::Starting)
}
