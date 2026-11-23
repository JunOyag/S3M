//! Mode dossier sous Windows (`protocols.acces-applicatif#mode-dossier`) :
//! dossier synchronisé Cloud Files (cldapi, Windows 10 1709 et plus), sans
//! pilote à installer ni droit d'administration. Les fantômes sont créés à
//! l'ouverture d'un dossier, le contenu fourni à la lecture ; les
//! modifications locales sont relues après un temps de calme
//! ([`crate::folder_sync`]).

use std::collections::BTreeSet;
use std::ffi::c_void;
use std::io::Read;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, UNIX_EPOCH};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{HANDLE, NTSTATUS, STATUS_SUCCESS, STATUS_UNSUCCESSFUL};
use windows::Win32::Storage::CloudFilters::*;
use windows::Win32::Storage::FileSystem::{
    ReadDirectoryChangesW, FILE_BASIC_INFO, FILE_NOTIFY_CHANGE_DIR_NAME,
    FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SIZE,
};

use crate::drive::{Drive, Meta};
use crate::folder_sync::{apply_local_file, plan_refresh, Debounce, LocalEntry};

/// Signalement d'une écriture : `(chemin, taille)` (écriture différée).
pub type WriteHook = Arc<dyn Fn(&str, u64) + Send + Sync>;

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_SHARE_ALL: u32 = 0x7;
/// Morceau transmis par lecture (multiple de 4 Kio).
const CHUNK: u64 = 1 << 20;

/// Dossier synchronisé connecté.
pub struct Folder {
    root: PathBuf,
    /// Chemin de la racine sans lecteur, en minuscules (`\users\x\s3m`), pour
    /// relier les chemins des rappels.
    norm_root: String,
    drive: Arc<Mutex<Drive>>,
    on_write: WriteHook,
    /// Dossiers dont les fantômes ont été fournis (chemins du lecteur).
    populated: Mutex<BTreeSet<String>>,
    pending: Mutex<Debounce>,
    started: Instant,
}

fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
    s.encode_wide().chain(Some(0)).collect()
}

fn filetime(unix_s: u64) -> i64 {
    ((unix_s + 11_644_473_600) * 10_000_000) as i64
}

fn metadata(m: &Meta) -> CF_FS_METADATA {
    let t = filetime(m.modified_at);
    CF_FS_METADATA {
        BasicInfo: FILE_BASIC_INFO {
            CreationTime: filetime(m.created_at),
            LastAccessTime: t,
            LastWriteTime: t,
            ChangeTime: t,
            FileAttributes: if m.is_dir {
                FILE_ATTRIBUTE_DIRECTORY
            } else {
                FILE_ATTRIBUTE_ARCHIVE
            },
        },
        FileSize: if m.is_dir { 0 } else { m.size as i64 },
    }
}

/// Chemin du lecteur (`/a/b`) d'un chemin local sous la racine.
fn drive_path(root: &Path, full: &Path) -> Option<String> {
    let rel = full.strip_prefix(root).ok()?;
    let parts: Vec<String> = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    Some(format!("/{}", parts.join("/")))
}

fn local_path(root: &Path, path: &str) -> PathBuf {
    let mut p = root.to_path_buf();
    for part in path.split('/').filter(|s| !s.is_empty()) {
        p.push(part);
    }
    p
}

fn open(path: &Path, write: bool) -> std::io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    if write {
        o.read(true).write(true);
    } else {
        // FILE_READ_ATTRIBUTES seul : n'hydrate pas le fichier.
        o.access_mode(0x80);
    }
    o.share_mode(FILE_SHARE_ALL)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
}

fn handle(f: &std::fs::File) -> HANDLE {
    HANDLE(f.as_raw_handle())
}

/// `Some(synchronisé)` pour un fantôme, `None` pour un fichier ordinaire.
fn placeholder_state(f: &std::fs::File) -> Option<bool> {
    let mut buf = [0u8; 512];
    unsafe {
        CfGetPlaceholderInfo(
            handle(f),
            CF_PLACEHOLDER_INFO_BASIC,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u32,
            None,
        )
        .ok()?;
        let info = &*(buf.as_ptr() as *const CF_PLACEHOLDER_BASIC_INFO);
        Some(info.InSyncState == CF_IN_SYNC_STATE_IN_SYNC)
    }
}

fn mtime_s(m: &std::fs::Metadata) -> u64 {
    m.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Folder {
    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    /// Chemin du lecteur d'un chemin normalisé de rappel (`\Users\…`).
    fn callback_path(&self, p: PCWSTR) -> Option<String> {
        if p.is_null() {
            return None;
        }
        let s = unsafe { p.to_string() }.ok()?;
        let low = s.to_lowercase();
        let rest = low.strip_prefix(&self.norm_root)?;
        if !(rest.is_empty() || rest.starts_with('\\')) {
            return None;
        }
        let rest = &s[s.len() - rest.len()..];
        let parts: Vec<&str> = rest.split('\\').filter(|x| !x.is_empty()).collect();
        Some(format!("/{}", parts.join("/")))
    }

    fn op(info: &CF_CALLBACK_INFO, ty: CF_OPERATION_TYPE) -> CF_OPERATION_INFO {
        CF_OPERATION_INFO {
            StructSize: std::mem::size_of::<CF_OPERATION_INFO>() as u32,
            Type: ty,
            ConnectionKey: info.ConnectionKey,
            TransferKey: info.TransferKey,
            CorrelationVector: info.CorrelationVector,
            SyncStatus: std::ptr::null(),
            RequestKey: info.RequestKey,
        }
    }

    fn transfer(info: &CF_CALLBACK_INFO, off: u64, data: &[u8], status: NTSTATUS, len: u64) {
        let op = Self::op(info, CF_OPERATION_TYPE_TRANSFER_DATA);
        let mut p = CF_OPERATION_PARAMETERS {
            ParamSize: std::mem::size_of::<CF_OPERATION_PARAMETERS>() as u32,
            Anonymous: CF_OPERATION_PARAMETERS_0 {
                TransferData: CF_OPERATION_PARAMETERS_0_0 {
                    Flags: CF_OPERATION_TRANSFER_DATA_FLAG_NONE,
                    CompletionStatus: status,
                    Buffer: data.as_ptr() as *const c_void,
                    Offset: off as i64,
                    Length: len as i64,
                },
            },
        };
        let _ = unsafe { CfExecute(&op, &mut p) };
    }

    fn fetch_data(&self, info: &CF_CALLBACK_INFO, p: &CF_CALLBACK_PARAMETERS_0_1) {
        let size = info.FileSize.max(0) as u64;
        let start = (p.RequiredFileOffset.max(0) as u64) & !4095;
        let end = (p.RequiredFileOffset.max(0) as u64 + p.RequiredLength.max(0) as u64)
            .div_ceil(4096)
            .saturating_mul(4096)
            .min(size);
        let Some(path) = self.callback_path(info.NormalizedPath) else {
            Self::transfer(info, start, &[], STATUS_UNSUCCESSFUL, end - start);
            return;
        };
        let mut off = start;
        while off < end {
            let len = CHUNK.min(end - off);
            let r = self.drive.lock().unwrap().read(&path, off, len as usize);
            match r {
                Ok(data) if data.len() as u64 == len => {
                    Self::transfer(info, off, &data, STATUS_SUCCESS, len)
                }
                _ => {
                    Self::transfer(info, off, &[], STATUS_UNSUCCESSFUL, end - off);
                    return;
                }
            }
            off += len;
        }
    }

    fn fetch_placeholders(&self, info: &CF_CALLBACK_INFO) {
        let path = self.callback_path(info.NormalizedPath);
        let list = path
            .as_ref()
            .map(|p| self.drive.lock().unwrap().list(p).map_err(|_| ()))
            .unwrap_or(Err(()));
        let op = Self::op(info, CF_OPERATION_TYPE_TRANSFER_PLACEHOLDERS);
        let (status, entries) = match list {
            Ok(l) => (STATUS_SUCCESS, l),
            Err(()) => (STATUS_UNSUCCESSFUL, Vec::new()),
        };
        let dir = path.unwrap_or_default();
        let names: Vec<Vec<u16>> = entries
            .iter()
            .map(|(n, _)| wide(std::ffi::OsStr::new(n)))
            .collect();
        let ids: Vec<Vec<u8>> = entries
            .iter()
            .map(|(n, _)| join(&dir, n).into_bytes())
            .collect();
        let mut infos: Vec<CF_PLACEHOLDER_CREATE_INFO> = entries
            .iter()
            .enumerate()
            .map(|(i, (_, m))| placeholder(&names[i], &ids[i], m))
            .collect();
        let mut p = CF_OPERATION_PARAMETERS {
            ParamSize: std::mem::size_of::<CF_OPERATION_PARAMETERS>() as u32,
            Anonymous: CF_OPERATION_PARAMETERS_0 {
                TransferPlaceholders: CF_OPERATION_PARAMETERS_0_4 {
                    Flags: CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_DISABLE_ON_DEMAND_POPULATION,
                    CompletionStatus: status,
                    PlaceholderTotalCount: infos.len() as i64,
                    PlaceholderArray: if infos.is_empty() {
                        std::ptr::null_mut()
                    } else {
                        infos.as_mut_ptr()
                    },
                    PlaceholderCount: infos.len() as u32,
                    EntriesProcessed: 0,
                },
            },
        };
        if unsafe { CfExecute(&op, &mut p) }.is_ok() && status == STATUS_SUCCESS {
            self.populated.lock().unwrap().insert(dir);
        }
    }

    fn ack(info: &CF_CALLBACK_INFO, rename: bool, ok: bool) {
        let status = if ok {
            STATUS_SUCCESS
        } else {
            STATUS_UNSUCCESSFUL
        };
        let ty = if rename {
            CF_OPERATION_TYPE_ACK_RENAME
        } else {
            CF_OPERATION_TYPE_ACK_DELETE
        };
        let op = Self::op(info, ty);
        let mut p = CF_OPERATION_PARAMETERS {
            ParamSize: std::mem::size_of::<CF_OPERATION_PARAMETERS>() as u32,
            Anonymous: if rename {
                CF_OPERATION_PARAMETERS_0 {
                    AckRename: CF_OPERATION_PARAMETERS_0_6 {
                        Flags: CF_OPERATION_ACK_RENAME_FLAG_NONE,
                        CompletionStatus: status,
                    },
                }
            } else {
                CF_OPERATION_PARAMETERS_0 {
                    AckDelete: CF_OPERATION_PARAMETERS_0_7 {
                        Flags: CF_OPERATION_ACK_DELETE_FLAG_NONE,
                        CompletionStatus: status,
                    },
                }
            },
        };
        let _ = unsafe { CfExecute(&op, &mut p) };
    }

    fn delete(&self, info: &CF_CALLBACK_INFO) {
        let ok = match self.callback_path(info.NormalizedPath) {
            Some(path) => {
                let mut d = self.drive.lock().unwrap();
                match d.stat(&path) {
                    Ok(None) => true,
                    Ok(Some(_)) => {
                        let r = d.remove(&path).is_ok();
                        drop(d);
                        if r {
                            (self.on_write)(&path, 0);
                            self.forget(&path);
                        }
                        r
                    }
                    Err(_) => false,
                }
            }
            None => false,
        };
        Self::ack(info, false, ok);
    }

    fn rename(&self, info: &CF_CALLBACK_INFO, p: &CF_CALLBACK_PARAMETERS_0_10) {
        let from = self.callback_path(info.NormalizedPath);
        let to = if (p.Flags.0 & CF_CALLBACK_RENAME_FLAG_TARGET_IN_SCOPE.0) != 0 {
            self.callback_path(p.TargetPath)
        } else {
            None
        };
        let ok = match (from, to) {
            (Some(from), Some(to)) => {
                let r = self.drive.lock().unwrap().rename(&from, &to, true);
                match r {
                    Ok(()) => {
                        (self.on_write)(&to, 0);
                        let mut pop = self.populated.lock().unwrap();
                        let moved: Vec<String> = pop
                            .iter()
                            .filter(|d| *d == &from || d.starts_with(&format!("{from}/")))
                            .cloned()
                            .collect();
                        for d in moved {
                            pop.remove(&d);
                            pop.insert(format!("{to}{}", &d[from.len()..]));
                        }
                        true
                    }
                    // Pas encore dans le lecteur (fichier local récent) : la
                    // surveillance l'enregistrera sous son nouveau nom.
                    Err(crate::drive::DriveError::NotFound) => true,
                    Err(_) => false,
                }
            }
            // Sortie du dossier : retrait du lecteur.
            (Some(from), None) => {
                let r = self.drive.lock().unwrap().remove(&from);
                match r {
                    Ok(()) | Err(crate::drive::DriveError::NotFound) => {
                        (self.on_write)(&from, 0);
                        self.forget(&from);
                        true
                    }
                    Err(_) => false,
                }
            }
            _ => false,
        };
        Self::ack(info, true, ok);
    }

    fn forget(&self, path: &str) {
        self.populated
            .lock()
            .unwrap()
            .retain(|d| d != path && !d.starts_with(&format!("{path}/")));
    }

    /// Enregistre un élément créé ou modifié localement.
    fn process_local(&self, full: &Path) {
        let Some(path) = drive_path(&self.root, full) else {
            return;
        };
        if path == "/" {
            return;
        }
        let Ok(meta) = std::fs::metadata(full) else {
            return;
        };
        let Ok(f) = open(full, !meta.is_dir()) else {
            // Fichier tenu par une application : nouvel essai plus tard.
            let now = self.now_ms();
            self.pending
                .lock()
                .unwrap()
                .touch(&full.to_string_lossy(), now);
            return;
        };
        let state = placeholder_state(&f);
        if state == Some(true) {
            return;
        }
        if meta.is_dir() {
            let created = {
                let mut d = self.drive.lock().unwrap();
                match d.stat(&path) {
                    Ok(None) => d.create(&path, true).is_ok(),
                    _ => false,
                }
            };
            if created {
                (self.on_write)(&path, 0);
            }
            if state.is_none() {
                let id = path.as_bytes();
                let _ = unsafe {
                    CfConvertToPlaceholder(
                        handle(&f),
                        Some(id.as_ptr() as *const c_void),
                        id.len() as u32,
                        CF_CONVERT_FLAG_MARK_IN_SYNC,
                        None,
                        None,
                    )
                };
            }
            self.populated.lock().unwrap().insert(path);
            return;
        }
        let mut content = Vec::new();
        let mut reader = &f;
        if reader.read_to_end(&mut content).is_err() {
            return;
        }
        let before = mtime_s(&meta);
        let r = {
            let mut d = self.drive.lock().unwrap();
            apply_local_file(&mut d, &path, &content).and_then(|c| Ok((c, d.stat(&path)?)))
        };
        let Ok((changed, Some(stored))) = r else {
            return;
        };
        if changed {
            (self.on_write)(&path, content.len() as u64);
        }
        let id = path.as_bytes();
        unsafe {
            if state.is_none() {
                let _ = CfConvertToPlaceholder(
                    handle(&f),
                    Some(id.as_ptr() as *const c_void),
                    id.len() as u32,
                    CF_CONVERT_FLAG_MARK_IN_SYNC,
                    None,
                    None,
                );
            }
            // Dates du lecteur, pour que la comparaison distante reste juste.
            let md = metadata(&stored);
            let _ = CfUpdatePlaceholder(
                handle(&f),
                Some(&md),
                None,
                0,
                None,
                CF_UPDATE_FLAG_MARK_IN_SYNC,
                None,
                None,
            );
        }
        // Écrit pendant l'enregistrement : à refaire.
        let after = std::fs::metadata(full).map(|m| m.len()).unwrap_or(0);
        let rewritten = std::fs::metadata(full).map(|m| mtime_s(&m)).unwrap_or(0) > before;
        if after != content.len() as u64 || rewritten {
            unsafe {
                let _ = CfSetInSyncState(
                    handle(&f),
                    CF_IN_SYNC_STATE_NOT_IN_SYNC,
                    CF_SET_IN_SYNC_FLAG_NONE,
                    None,
                );
            }
            let now = self.now_ms();
            self.pending
                .lock()
                .unwrap()
                .touch(&full.to_string_lossy(), now);
        }
    }

    /// Met à jour les fantômes des dossiers ouverts après un changement
    /// distant.
    fn refresh(&self) {
        let mut dirs: Vec<String> = self.populated.lock().unwrap().iter().cloned().collect();
        // « Partagés avec moi » est toujours suivi : ouvert vide avant
        // l'arrivée d'un partage, Windows ne redemanderait pas son contenu.
        if self.drive.lock().unwrap().shared.is_some()
            && !dirs.iter().any(|d| d == crate::drive::SHARED_DIR)
        {
            dirs.push(crate::drive::SHARED_DIR.to_string());
        }
        for dir in dirs {
            let remote = match self.drive.lock().unwrap().list(&dir) {
                Ok(l) => l,
                Err(_) => continue,
            };
            let local_dir = local_path(&self.root, &dir);
            let Ok(rd) = std::fs::read_dir(&local_dir) else {
                continue;
            };
            let local: Vec<LocalEntry> = rd
                .flatten()
                .filter_map(|e| {
                    let m = e.metadata().ok()?;
                    let in_sync = open(&e.path(), false)
                        .ok()
                        .and_then(|f| placeholder_state(&f))
                        .unwrap_or(false);
                    Some(LocalEntry {
                        name: e.file_name().to_string_lossy().into_owned(),
                        is_dir: m.is_dir(),
                        in_sync,
                        size: m.len(),
                        modified_at: mtime_s(&m),
                    })
                })
                .collect();
            let plan = plan_refresh(&remote, &local);
            let meta_of = |n: &str| remote.iter().find(|(x, _)| x == n).map(|(_, m)| *m);
            if !plan.create.is_empty() {
                let names: Vec<Vec<u16>> = plan
                    .create
                    .iter()
                    .map(|n| wide(std::ffi::OsStr::new(n)))
                    .collect();
                let ids: Vec<Vec<u8>> = plan
                    .create
                    .iter()
                    .map(|n| join(&dir, n).into_bytes())
                    .collect();
                let metas: Vec<Meta> = plan.create.iter().filter_map(|n| meta_of(n)).collect();
                if metas.len() == names.len() {
                    let mut infos: Vec<CF_PLACEHOLDER_CREATE_INFO> = (0..names.len())
                        .map(|i| placeholder(&names[i], &ids[i], &metas[i]))
                        .collect();
                    let base = wide(local_dir.as_os_str());
                    let _ = unsafe {
                        CfCreatePlaceholders(
                            PCWSTR(base.as_ptr()),
                            &mut infos,
                            CF_CREATE_FLAG_NONE,
                            None,
                        )
                    };
                }
            }
            for n in &plan.remove {
                let p = local_dir.join(n);
                let _ = if p.is_dir() {
                    std::fs::remove_dir_all(&p)
                } else {
                    std::fs::remove_file(&p)
                };
            }
            for n in &plan.update {
                let (Some(m), Ok(f)) = (meta_of(n), open(&local_dir.join(n), true)) else {
                    continue;
                };
                let md = metadata(&m);
                let size = std::fs::metadata(local_dir.join(n))
                    .map(|x| x.len())
                    .unwrap_or(0);
                let range = [CF_FILE_RANGE {
                    StartingOffset: 0,
                    Length: size.max(m.size) as i64,
                }];
                let _ = unsafe {
                    CfUpdatePlaceholder(
                        handle(&f),
                        Some(&md),
                        None,
                        0,
                        Some(&range),
                        CF_UPDATE_FLAG_MARK_IN_SYNC | CF_UPDATE_FLAG_DEHYDRATE,
                        None,
                        None,
                    )
                };
            }
        }
    }
}

fn join(dir: &str, name: &str) -> String {
    if dir == "/" || dir.is_empty() {
        format!("/{name}")
    } else {
        format!("{dir}/{name}")
    }
}

fn placeholder(name: &[u16], id: &[u8], m: &Meta) -> CF_PLACEHOLDER_CREATE_INFO {
    CF_PLACEHOLDER_CREATE_INFO {
        RelativeFileName: PCWSTR(name.as_ptr()),
        FsMetadata: metadata(m),
        FileIdentity: id.as_ptr() as *const c_void,
        FileIdentityLength: id.len() as u32,
        Flags: CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC,
        Result: windows::core::HRESULT(0),
        CreateUsn: 0,
    }
}

// ------------------------------------------------------------- rappels

unsafe fn folder<'a>(info: *const CF_CALLBACK_INFO) -> Option<(&'a Folder, &'a CF_CALLBACK_INFO)> {
    let info = info.as_ref()?;
    let f = (info.CallbackContext as *const Folder).as_ref()?;
    Some((f, info))
}

unsafe extern "system" fn on_fetch_data(
    info: *const CF_CALLBACK_INFO,
    p: *const CF_CALLBACK_PARAMETERS,
) {
    if let (Some((f, info)), Some(p)) = (folder(info), p.as_ref()) {
        f.fetch_data(info, &p.Anonymous.FetchData);
    }
}

unsafe extern "system" fn on_fetch_placeholders(
    info: *const CF_CALLBACK_INFO,
    _: *const CF_CALLBACK_PARAMETERS,
) {
    if let Some((f, info)) = folder(info) {
        f.fetch_placeholders(info);
    }
}

unsafe extern "system" fn on_delete(
    info: *const CF_CALLBACK_INFO,
    _: *const CF_CALLBACK_PARAMETERS,
) {
    if let Some((f, info)) = folder(info) {
        f.delete(info);
    }
}

unsafe extern "system" fn on_rename(
    info: *const CF_CALLBACK_INFO,
    p: *const CF_CALLBACK_PARAMETERS,
) {
    if let (Some((f, info)), Some(p)) = (folder(info), p.as_ref()) {
        f.rename(info, &p.Anonymous.Rename);
    }
}

// ------------------------------------------------------------ démarrage

/// Enregistre et connecte le dossier `root`, puis lance la surveillance des
/// modifications locales et distantes. Le dossier reste connecté jusqu'à la
/// fin du processus.
pub fn start(root: &Path, drive: Arc<Mutex<Drive>>, on_write: WriteHook) -> Result<(), String> {
    std::fs::create_dir_all(root).map_err(|e| format!("dossier {} : {e}", root.display()))?;
    let root = std::fs::canonicalize(root).map_err(|e| e.to_string())?;
    // `\\?\C:\…` → `C:\…`.
    let root = PathBuf::from(
        root.to_string_lossy()
            .trim_start_matches(r"\\?\")
            .to_string(),
    );
    let s = root.to_string_lossy().to_string();
    let norm_root = s
        .get(2..)
        .filter(|_| s.as_bytes().get(1) == Some(&b':'))
        .ok_or("le dossier doit être sur un disque local (C:, D:…)")?
        .trim_end_matches('\\')
        .to_lowercase();
    let wroot = wide(root.as_os_str());
    let provider = wide(std::ffi::OsStr::new("S3m"));
    let version = wide(std::ffi::OsStr::new("1"));
    let identity = b"s3m";
    let reg = CF_SYNC_REGISTRATION {
        StructSize: std::mem::size_of::<CF_SYNC_REGISTRATION>() as u32,
        ProviderName: PCWSTR(provider.as_ptr()),
        ProviderVersion: PCWSTR(version.as_ptr()),
        SyncRootIdentity: identity.as_ptr() as *const c_void,
        SyncRootIdentityLength: identity.len() as u32,
        FileIdentity: std::ptr::null(),
        FileIdentityLength: 0,
        ProviderId: windows::core::GUID::from_u128(0x5f3a_6d2e_9b41_4c7a_8e15_3c0d_7a92_b4e1),
    };
    let policies = CF_SYNC_POLICIES {
        StructSize: std::mem::size_of::<CF_SYNC_POLICIES>() as u32,
        Hydration: CF_HYDRATION_POLICY {
            Primary: CF_HYDRATION_POLICY_FULL,
            Modifier: CF_HYDRATION_POLICY_MODIFIER_NONE,
        },
        Population: CF_POPULATION_POLICY {
            Primary: CF_POPULATION_POLICY_FULL,
            Modifier: CF_POPULATION_POLICY_MODIFIER_NONE,
        },
        InSync: CF_INSYNC_POLICY_TRACK_ALL,
        HardLink: CF_HARDLINK_POLICY_NONE,
        PlaceholderManagement: CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT,
    };
    unsafe {
        CfRegisterSyncRoot(
            PCWSTR(wroot.as_ptr()),
            &reg,
            &policies,
            CF_REGISTER_FLAG_UPDATE,
        )
    }
    .map_err(|e| format!("dossier synchronisé refusé par Windows : {e}"))?;

    // Dossiers déjà présents localement (lancement précédent) : ouverts.
    let mut populated = BTreeSet::from(["/".to_string()]);
    let mut stack = vec![root.clone()];
    while let Some(d) = stack.pop() {
        if let Ok(rd) = std::fs::read_dir(&d) {
            for e in rd.flatten() {
                if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    let p = e.path();
                    if std::fs::read_dir(&p)
                        .map(|mut r| r.next().is_some())
                        .unwrap_or(false)
                    {
                        if let Some(dp) = drive_path(&root, &p) {
                            populated.insert(dp);
                        }
                    }
                    stack.push(p);
                }
            }
        }
    }
    let folder: &'static Folder = Box::leak(Box::new(Folder {
        root: root.clone(),
        norm_root,
        drive,
        on_write,
        populated: Mutex::new(populated),
        pending: Mutex::new(Debounce::default()),
        started: Instant::now(),
    }));
    let table = [
        CF_CALLBACK_REGISTRATION {
            Type: CF_CALLBACK_TYPE_FETCH_DATA,
            Callback: Some(on_fetch_data),
        },
        CF_CALLBACK_REGISTRATION {
            Type: CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS,
            Callback: Some(on_fetch_placeholders),
        },
        CF_CALLBACK_REGISTRATION {
            Type: CF_CALLBACK_TYPE_NOTIFY_DELETE,
            Callback: Some(on_delete),
        },
        CF_CALLBACK_REGISTRATION {
            Type: CF_CALLBACK_TYPE_NOTIFY_RENAME,
            Callback: Some(on_rename),
        },
        CF_CALLBACK_REGISTRATION {
            Type: CF_CALLBACK_TYPE_NONE,
            Callback: None,
        },
    ];
    unsafe {
        CfConnectSyncRoot(
            PCWSTR(wroot.as_ptr()),
            table.as_ptr(),
            Some(folder as *const Folder as *const c_void),
            CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH,
        )
    }
    .map_err(|e| format!("connexion du dossier synchronisé : {e}"))?;

    // La racine n'est pas un fantôme : ses entrées sont fournies ici, puis
    // celles des dossiers ouverts lors d'un lancement précédent.
    folder.refresh();
    // Surveillance des modifications locales.
    std::thread::spawn(move || watch(folder));
    // Traitement après le temps de calme, et changements distants.
    std::thread::spawn(move || {
        let mut last_root = folder.drive.lock().unwrap().root_hash();
        let mut last_shared = folder.drive.lock().unwrap().shared_version();
        loop {
            std::thread::sleep(Duration::from_millis(500));
            let now = folder.now_ms();
            let due = folder.pending.lock().unwrap().due(now);
            for p in due {
                folder.process_local(Path::new(&p));
            }
            let (r, v) = {
                let d = folder.drive.lock().unwrap();
                (d.root_hash(), d.shared_version())
            };
            // Nouvelle racine, ou partages reçus changés : dossiers ouverts
            // mis à jour.
            if r != last_root || v != last_shared {
                last_root = r;
                last_shared = v;
                folder.refresh();
            }
        }
    });
    Ok(())
}

fn watch(folder: &'static Folder) {
    let Ok(dir) = std::fs::OpenOptions::new()
        .access_mode(0x1) // FILE_LIST_DIRECTORY
        .share_mode(FILE_SHARE_ALL)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(&folder.root)
    else {
        return;
    };
    let mut buf = vec![0u32; 16_384];
    loop {
        let mut n = 0u32;
        let r = unsafe {
            ReadDirectoryChangesW(
                handle(&dir),
                buf.as_mut_ptr() as *mut c_void,
                (buf.len() * 4) as u32,
                true,
                FILE_NOTIFY_CHANGE_FILE_NAME
                    | FILE_NOTIFY_CHANGE_DIR_NAME
                    | FILE_NOTIFY_CHANGE_SIZE
                    | FILE_NOTIFY_CHANGE_LAST_WRITE,
                Some(&mut n),
                None,
                None,
            )
        };
        if r.is_err() {
            std::thread::sleep(Duration::from_secs(1));
            continue;
        }
        let now = folder.now_ms();
        let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n as usize) };
        let mut off = 0usize;
        while off + 12 <= bytes.len() {
            let next = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap()) as usize;
            let len = u32::from_le_bytes(bytes[off + 8..off + 12].try_into().unwrap()) as usize;
            let name: Vec<u16> = bytes[off + 12..(off + 12 + len).min(bytes.len())]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect();
            let rel = String::from_utf16_lossy(&name);
            let full = folder.root.join(rel);
            folder
                .pending
                .lock()
                .unwrap()
                .touch(&full.to_string_lossy(), now);
            if next == 0 {
                break;
            }
            off += next;
        }
    }
}

/// Retire l'enregistrement du dossier synchronisé `root` (changement
/// d'emplacement, tests). Les fichiers locaux restent en place.
pub fn unregister(root: &Path) -> Result<(), String> {
    let w = wide(root.as_os_str());
    unsafe { CfUnregisterSyncRoot(PCWSTR(w.as_ptr())) }.map_err(|e| e.to_string())
}
