//! Mode dossier (`protocols.acces-applicatif#mode-dossier`), partie commune
//! à tous les systèmes : enregistrement d'un fichier modifié localement par
//! blocs, plan de mise à jour des fantômes d'un dossier, attente du calme
//! avant relecture. Les appels au système (Cloud Files sous Windows) sont
//! dans `cloud_folder`.

use std::collections::BTreeMap;

use crate::drive::{Drive, DriveError, Meta};

/// Taille des blocs comparés (celle des blocs du protocole).
pub const BLOCK: usize = 65_536;
/// Délai sans nouvelle écriture avant relecture d'un fichier modifié.
pub const QUIET_MS: u64 = 2_000;

/// Enregistre le contenu `content` du fichier local `path` dans le lecteur :
/// création au besoin, puis seuls les blocs qui diffèrent sont écrits.
/// Renvoie `true` si quelque chose a changé.
pub fn apply_local_file(drive: &mut Drive, path: &str, content: &[u8]) -> Result<bool, DriveError> {
    let old_size = match drive.stat(path)? {
        Some(m) if m.is_dir => return Err(DriveError::IsADirectory),
        Some(m) => m.size,
        None => {
            drive.create(path, false)?;
            0
        }
    };
    let mut changed = false;
    for (i, chunk) in content.chunks(BLOCK).enumerate() {
        let off = (i * BLOCK) as u64;
        let same = off < old_size && drive.read(path, off, chunk.len())? == chunk;
        if !same {
            drive.write(path, off, chunk)?;
            changed = true;
        }
    }
    if old_size != content.len() as u64 {
        drive.set_size(path, content.len() as u64)?;
        changed = true;
    }
    Ok(changed)
}

/// Entrée locale d'un dossier déjà ouvert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalEntry {
    pub name: String,
    pub is_dir: bool,
    /// Fantôme géré et synchronisé (ni nouveau, ni modifié localement).
    pub in_sync: bool,
    pub size: u64,
    pub modified_at: u64,
}

/// Mise à jour des fantômes d'un dossier après un changement distant.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RefreshPlan {
    /// Absents localement : fantômes à créer.
    pub create: Vec<String>,
    /// Absents du lecteur et synchronisés : à retirer.
    pub remove: Vec<String>,
    /// Fichiers synchronisés dont la taille ou la date a changé : fantômes à
    /// remplacer (contenu local libéré).
    pub update: Vec<String>,
}

/// Compare le lecteur et le dossier local. Un élément créé ou modifié
/// localement et pas encore enregistré (`in_sync` faux) n'est jamais
/// retiré ni remplacé. Comparaison des noms sans casse, comme Windows.
pub fn plan_refresh(remote: &[(String, Meta)], local: &[LocalEntry]) -> RefreshPlan {
    let key = |n: &str| n.to_lowercase();
    let r: BTreeMap<String, (&String, &Meta)> =
        remote.iter().map(|(n, m)| (key(n), (n, m))).collect();
    let l: BTreeMap<String, &LocalEntry> = local.iter().map(|e| (key(&e.name), e)).collect();
    let mut plan = RefreshPlan::default();
    for (k, (name, _)) in &r {
        if !l.contains_key(k) {
            plan.create.push((*name).clone());
        }
    }
    for (k, e) in &l {
        if !e.in_sync {
            continue;
        }
        match r.get(k) {
            None => plan.remove.push(e.name.clone()),
            Some((_, m)) if !m.is_dir && !e.is_dir => {
                if m.size != e.size || m.modified_at != e.modified_at {
                    plan.update.push(e.name.clone());
                }
            }
            Some(_) => {}
        }
    }
    plan
}

/// Chemins signalés modifiés, relus après [`QUIET_MS`] sans nouvel
/// événement.
#[derive(Debug, Default)]
pub struct Debounce {
    seen: BTreeMap<String, u64>,
}

impl Debounce {
    pub fn touch(&mut self, path: &str, now_ms: u64) {
        self.seen.insert(path.to_string(), now_ms);
    }

    /// Chemins calmes depuis [`QUIET_MS`], retirés de l'attente.
    pub fn due(&mut self, now_ms: u64) -> Vec<String> {
        let ready: Vec<String> = self
            .seen
            .iter()
            .filter(|(_, t)| now_ms >= **t + QUIET_MS)
            .map(|(p, _)| p.clone())
            .collect();
        for p in &ready {
            self.seen.remove(p);
        }
        ready
    }
}

/// Bilan d'une libération d'espace (dossier synchronisé).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Freed {
    pub files: u64,
    pub bytes: u64,
}
