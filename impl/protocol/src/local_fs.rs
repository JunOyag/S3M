//! Explorateur de dossiers des tableaux de bord (`deploiement.packaging#retours`) :
//! racines (disques Windows, points de montage Linux et macOS), dossiers,
//! création d'un dossier et espace du disque. Seule exception au « sans
//! I/O » de cette bibliothèque : le Nœud et le Connecteur en ont besoin tous
//! deux, pour la machine locale seulement.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

/// Espace du système de fichiers qui contient un chemin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Space {
    pub total: u64,
    pub free: u64,
}

/// Premier ancêtre existant (un dossier pas encore créé prend l'espace de
/// son disque).
fn existing(p: &Path) -> Option<PathBuf> {
    let mut cur = Some(p);
    while let Some(c) = cur {
        if c.exists() {
            return Some(c.to_path_buf());
        }
        cur = c.parent();
    }
    None
}

#[cfg(windows)]
fn space_of(p: &Path) -> Option<Space> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let w: Vec<u16> = p.as_os_str().encode_wide().chain(Some(0)).collect();
    let (mut avail, mut total, mut free) = (0u64, 0u64, 0u64);
    // SAFETY : chaîne terminée par 0 et pointeurs valides pendant l'appel.
    let ok = unsafe { GetDiskFreeSpaceExW(w.as_ptr(), &mut avail, &mut total, &mut free) };
    (ok != 0).then_some(Space { total, free: avail })
}

#[cfg(unix)]
fn space_of(p: &Path) -> Option<Space> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(p.as_os_str().as_bytes()).ok()?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY : chaîne C valide, structure de sortie possédée.
    if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
        return None;
    }
    let unit = s.f_frsize as u64;
    Some(Space {
        total: s.f_blocks as u64 * unit,
        free: s.f_bavail as u64 * unit,
    })
}

#[cfg(not(any(windows, unix)))]
fn space_of(_: &Path) -> Option<Space> {
    None
}

/// Espace du disque qui contient (ou contiendra) `p`.
pub fn space(p: &Path) -> Option<Space> {
    space_of(&existing(p)?)
}

/// Dossier personnel de l'utilisateur.
pub fn home() -> PathBuf {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Racines proposées : disques présents (Windows) ; `/`, le dossier
/// personnel et les points de montage des disques externes (Linux :
/// `/media`, `/run/media`, `/mnt` ; macOS : `/Volumes`).
pub fn roots() -> Vec<String> {
    let mut out = Vec::new();
    if cfg!(windows) {
        for c in b'A'..=b'Z' {
            let r = format!("{}:\\", c as char);
            if Path::new(&r).exists() {
                out.push(r);
            }
        }
    } else {
        out.push("/".to_string());
        let mut scan = |base: &str, depth: usize| {
            let mut level = vec![PathBuf::from(base)];
            for _ in 0..depth {
                let mut next = Vec::new();
                for d in level {
                    if let Ok(rd) = std::fs::read_dir(&d) {
                        next.extend(rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()));
                    }
                }
                level = next;
            }
            out.extend(level.into_iter().map(|p| p.display().to_string()));
        };
        scan("/Volumes", 1);
        scan("/media", 2);
        scan("/run/media", 2);
        scan("/mnt", 1);
    }
    let h = home().display().to_string();
    if !out.contains(&h) {
        out.insert(usize::from(!cfg!(windows)).min(out.len()), h);
    }
    out
}

/// Lettres de lecteur libres (Windows), de `D:` à `Z:`.
pub fn free_letters() -> Vec<String> {
    if !cfg!(windows) {
        return Vec::new();
    }
    (b'D'..=b'Z')
        .map(|c| format!("{}:", c as char))
        .filter(|l| !Path::new(&format!("{l}\\")).exists())
        .collect()
}

fn space_json(s: Option<Space>) -> Value {
    match s {
        Some(s) => json!({
            "total (octets)": s.total,
            "disponible (octets)": s.free,
            "restant (%)": if s.total == 0 { 0.0 } else { (s.free as f64 * 1000.0 / s.total as f64).round() / 10.0 },
        }),
        None => Value::Null,
    }
}

/// Action `fs_browse` : contenu du dossier `chemin` (dossier personnel si
/// vide) ; avec `espace seul`, l'espace seulement (le dossier peut ne pas
/// encore exister).
pub fn browse(v: &Value) -> Result<Value, String> {
    let raw = v.get("chemin").and_then(Value::as_str).unwrap_or("").trim();
    let only_space = v.get("espace seul").and_then(Value::as_bool) == Some(true);
    let mut p = if raw.is_empty() {
        home()
    } else {
        PathBuf::from(raw)
    };
    // Chemin d'un fichier : son dossier.
    if p.is_file() {
        if let Some(up) = p.parent() {
            p = up.to_path_buf();
        }
    }
    if only_space {
        return Ok(
            json!({ "ok": true, "données": { "chemin": p.display().to_string(), "espace": space_json(space(&p)) } }),
        );
    }
    if !p.is_dir() {
        return Err(format!("dossier introuvable : {}", p.display()));
    }
    let mut dirs: Vec<String> = std::fs::read_dir(&p)
        .map_err(|e| format!("{} : {e}", p.display()))?
        .flatten()
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| !n.starts_with('.') && !n.starts_with('$'))
        .collect();
    dirs.sort_by_key(|n| n.to_lowercase());
    Ok(json!({ "ok": true, "données": {
        "chemin": p.display().to_string(),
        "parent": p.parent().map(|x| x.display().to_string()),
        "dossiers": dirs,
        "racines": roots(),
        "séparateur": std::path::MAIN_SEPARATOR.to_string(),
        "espace": space_json(space(&p)),
    } }))
}

/// Action `fs_mkdir` : crée le dossier `nom` dans `chemin`.
pub fn mkdir(v: &Value) -> Result<Value, String> {
    let parent = v.get("chemin").and_then(Value::as_str).unwrap_or("").trim();
    let name = v.get("nom").and_then(Value::as_str).unwrap_or("").trim();
    if parent.is_empty() {
        return Err("choisissez d'abord le dossier où le créer".into());
    }
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains(['/', '\\', ':', '*', '?', '"', '<', '>', '|'])
    {
        return Err("nom de dossier invalide".into());
    }
    let p = Path::new(parent).join(name);
    std::fs::create_dir(&p).map_err(|e| format!("{} : {e}", p.display()))?;
    Ok(
        json!({ "ok": true, "message": "Dossier créé", "données": { "chemin": p.display().to_string() } }),
    )
}
