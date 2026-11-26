//! Plusieurs identités dans `S3m.exe` (`deploiement.packaging#plusieurs-identites`) :
//! rangement des dossiers d'identité, ajout, retrait, état d'ensemble.

use std::path::{Path, PathBuf};

use crate::daemon::TrayState;
use crate::setup::config_path;

/// Dossier des identités ajoutées.
pub fn identities_dir(app: &Path) -> PathBuf {
    app.join("identites")
}

/// Identité créée : configurée, ou phrase présente (changement de Nœud en
/// cours, assistant à rouvrir).
fn started(dir: &Path) -> bool {
    config_path(dir).exists()
        || s3m_protocol::vault::storage(&dir.join("user.seed")) != s3m_protocol::vault::Storage::Missing
}

/// Identités à lancer : l'identité d'origine (`app`, configurée ou non),
/// puis les identités ajoutées configurées, par numéro croissant.
pub fn list(app: &Path) -> Vec<(u32, PathBuf)> {
    let mut added: Vec<(u32, PathBuf)> = std::fs::read_dir(identities_dir(app))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let n: u32 = e.file_name().to_str()?.parse().ok()?;
            let p = e.path();
            (n >= 2 && started(&p)).then_some((n, p))
        })
        .collect();
    added.sort();
    // L'identité d'origine est lancée si elle est configurée, si elle garde
    // sa phrase (changement de Nœud : configuration mise de côté, assistant
    // à rouvrir) ou s'il n'y a aucune autre identité (premier lancement) ;
    // retirée, son dossier ne garde ni l'une ni l'autre.
    let mut out = Vec::new();
    if started(app) || added.is_empty() {
        out.push((1, app.to_path_buf()));
    }
    out.extend(added);
    out
}

/// Fichiers propres à l'application dans son dossier, qui restent quand
/// l'identité d'origine est retirée.
const APP_FILES: &[&str] = &["logs", "s3m.lock", "identites", "setup.url"];

/// Dossier d'une nouvelle identité : premier numéro (à partir de 2) libre,
/// ou dont l'assistant n'a pas été terminé. Le dossier est créé.
pub fn next_dir(app: &Path) -> std::io::Result<(u32, PathBuf)> {
    let base = identities_dir(app);
    for n in 2u32.. {
        let p = base.join(n.to_string());
        if !started(&p) {
            std::fs::create_dir_all(&p)?;
            return Ok((n, p));
        }
    }
    unreachable!()
}

/// Retrait d'une identité : son dossier est renommé
/// `<n>.retiree-<horodatage>`, jamais effacé ; l'identité d'origine ne se
/// retire que s'il en reste une autre.
pub fn set_aside(app: &Path, dir: &Path, stamp: u64) -> Result<PathBuf, String> {
    let base = identities_dir(app);
    if dir == app {
        // Identité d'origine : seulement s'il en reste une autre ; ses
        // fichiers vont dans `identites\1.retiree-<horodatage>`.
        if !list(app).iter().any(|(n, _)| *n > 1) {
            return Err("c'est la seule identité : elle ne peut pas être retirée".into());
        }
        let to = base.join(format!("1.retiree-{stamp}"));
        std::fs::create_dir_all(&to).map_err(|e| e.to_string())?;
        for e in std::fs::read_dir(app).map_err(|e| e.to_string())?.flatten() {
            let name = e.file_name();
            if APP_FILES.iter().any(|f| name == *f) {
                continue;
            }
            std::fs::rename(e.path(), to.join(&name)).map_err(|e| e.to_string())?;
        }
        return Ok(to);
    }
    if dir.parent() != Some(base.as_path()) {
        return Err("dossier d'identité inattendu".into());
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

/// Identité archivée (retirée) : dossier `identites\<n>.retiree-<horodatage>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Archived {
    pub dir: PathBuf,
    /// Numéro qu'elle portait.
    pub num: u32,
    /// Date du retrait (secondes Unix).
    pub retired_at: u64,
    /// Pseudo enregistré (vide si aucun).
    pub pseudo: String,
}

impl Archived {
    /// Libellé du menu : pseudo (ou numéro) et date du retrait.
    pub fn label(&self) -> String {
        let who = match self.pseudo.is_empty() {
            true => format!("Identité {}", self.num),
            false => self.pseudo.clone(),
        };
        format!("{who} — archivée le {}", date_fr(self.retired_at))
    }
}

/// `JJ/MM/AAAA` (UTC) d'un instant Unix.
pub fn date_fr(t: u64) -> String {
    // Jours depuis 1970 → date civile (algorithme de H. Hinnant).
    let z = (t / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{d:02}/{m:02}/{y}")
}

/// Identités archivées, de la plus récente à la plus ancienne.
pub fn archived(app: &Path) -> Vec<Archived> {
    let mut out: Vec<Archived> = std::fs::read_dir(identities_dir(app))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_str()?.to_string();
            let (n, t) = name.split_once(".retiree-")?;
            let dir = e.path();
            let pseudo = std::fs::read(dir.join("data").join("names.json"))
                .ok()
                .and_then(|b| serde_json::from_slice::<crate::channel::Names>(&b).ok())
                .map(|n| n.pseudo)
                .unwrap_or_default();
            Some(Archived {
                num: n.parse().ok()?,
                retired_at: t.parse().ok()?,
                pseudo,
                dir,
            })
        })
        .collect();
    out.sort_by(|a, b| b.retired_at.cmp(&a.retired_at).then(a.dir.cmp(&b.dir)));
    out
}

/// Dossier archivé valide : directement dans `identites`, nommé
/// `<n>.retiree-<horodatage>`.
fn check_archived(app: &Path, dir: &Path) -> Result<(), String> {
    let ok = dir.parent() == Some(identities_dir(app).as_path())
        && dir
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.contains(".retiree-"));
    match ok {
        true => Ok(()),
        false => Err("dossier d'identité archivée inattendu".into()),
    }
}

/// Restaure une identité archivée sous le premier numéro libre (à partir
/// de 2) : `(numéro, dossier)`.
pub fn restore(app: &Path, dir: &Path) -> Result<(u32, PathBuf), String> {
    check_archived(app, dir)?;
    if !config_path(dir).exists() {
        return Err("cette identité n'avait pas de configuration : rien à restaurer".into());
    }
    let base = identities_dir(app);
    for n in 2u32.. {
        let to = base.join(n.to_string());
        if config_path(&to).exists() {
            continue;
        }
        // Dossier vide laissé par un assistant non terminé : remplacé.
        if to.exists() {
            let empty = std::fs::read_dir(&to)
                .map(|mut r| r.next().is_none())
                .unwrap_or(false);
            if !empty {
                continue;
            }
            std::fs::remove_dir(&to).map_err(|e| e.to_string())?;
        }
        std::fs::rename(dir, &to).map_err(|e| e.to_string())?;
        return Ok((n, to));
    }
    unreachable!()
}

/// Supprime définitivement une identité archivée de ce poste (phrase de
/// récupération comprise : seule la phrase notée permet de la retrouver).
pub fn purge(app: &Path, dir: &Path) -> Result<(), String> {
    check_archived(app, dir)?;
    // Phrase rangée dans le coffre du système : retirée aussi.
    s3m_protocol::vault::remove(&dir.join("user.seed"));
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        if e.file_name().to_string_lossy().starts_with("user.seed.revoquee-") {
            s3m_protocol::vault::remove(&e.path());
        }
    }
    std::fs::remove_dir_all(dir).map_err(|e| e.to_string())
}

/// Gravité : erreur > Nœud injoignable > suspendue > modifications en
/// attente ou synchronisation > démarrage > à jour.
fn rank(s: TrayState) -> u8 {
    match s {
        TrayState::Ok => 0,
        TrayState::Starting => 1,
        TrayState::Syncing => 2,
        TrayState::Paused => 3,
        TrayState::Offline => 4,
        TrayState::Error => 5,
    }
}

/// Nombre d'états qui ne sont pas « à jour ».
pub fn needing_attention(states: &[TrayState]) -> usize {
    states.iter().filter(|s| **s != TrayState::Ok).count()
}

/// État d'ensemble pour l'icône : celui de l'identité dans le pire état.
pub fn worst(states: &[TrayState]) -> TrayState {
    states
        .iter()
        .copied()
        .max_by_key(|s| rank(*s))
        .unwrap_or(TrayState::Starting)
}
