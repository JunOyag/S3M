//! Backend WinFsp du lecteur monté — id `protocols.acces-applicatif`
//! (Windows, feature `mount`). Réf. spec : docs/04-protocols/acces-applicatif.md.
//!
//! Traduit les appels du pilote WinFsp en opérations du moteur
//! [`crate::drive::Drive`]. Les suppressions sont appliquées au `cleanup`
//! (sémantique Windows « supprimer à la fermeture ») ; chaque fichier
//! modifié est signalé au planificateur d'écriture différée.

use std::ffi::c_void;
use std::sync::{Arc, Mutex};

use winfsp::filesystem::{
    DirBuffer, DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext, OpenFileInfo,
    VolumeInfo, WideNameInfo,
};
use winfsp::host::{FileSystemHost, FineGuard, VolumeParams};
use winfsp::{FspError, U16CStr};

use crate::drive::{Drive, DriveError, Meta};

const STATUS_END_OF_FILE: i32 = 0xC000_0011_u32 as i32;
/// Fichier hors ligne (Nœud injoignable, contenu absent de l'appareil).
const STATUS_FILE_IS_OFFLINE: i32 = 0xC000_0267_u32 as i32;
const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034_u32 as i32;
const STATUS_OBJECT_NAME_COLLISION: i32 = 0xC000_0035_u32 as i32;
const STATUS_FILE_IS_A_DIRECTORY: i32 = 0xC000_00BA_u32 as i32;
const STATUS_DIRECTORY_NOT_EMPTY: i32 = 0xC000_0101_u32 as i32;
const STATUS_ACCESS_DENIED: i32 = 0xC000_0022_u32 as i32;
const STATUS_NOT_A_DIRECTORY: i32 = 0xC000_0103_u32 as i32;
const STATUS_IO_DEVICE_ERROR: i32 = 0xC000_0185_u32 as i32;

const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;
const FSP_CLEANUP_DELETE: u32 = 0x01;

/// `O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)` sous forme binaire
/// auto-relative : accès complet pour l'utilisateur qui a monté le lecteur.
const SECURITY_DESCRIPTOR: &[u8] = &[
    1, 0, 4, 144, 20, 0, 0, 0, 36, 0, 0, 0, 0, 0, 0, 0, 52, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 5, 32, 0,
    0, 0, 32, 2, 0, 0, 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0, 2, 0, 72, 0, 3, 0, 0, 0,
    0, 0, 20, 0, 255, 1, 31, 0, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0, 0, 0, 24, 0, 255, 1, 31, 0, 1,
    2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0, 0, 0, 20, 0, 255, 1, 31, 0, 1, 1, 0, 0, 0, 0, 0,
    1, 0, 0, 0, 0,
];

fn ntstatus(e: DriveError) -> FspError {
    FspError::NTSTATUS(match e {
        DriveError::NotFound => STATUS_OBJECT_NAME_NOT_FOUND,
        DriveError::Exists => STATUS_OBJECT_NAME_COLLISION,
        DriveError::NotADirectory => STATUS_NOT_A_DIRECTORY,
        DriveError::IsADirectory => STATUS_FILE_IS_A_DIRECTORY,
        DriveError::NotEmpty => STATUS_DIRECTORY_NOT_EMPTY,
        DriveError::ReadOnly => STATUS_ACCESS_DENIED,
        _ => STATUS_IO_DEVICE_ERROR,
    })
}

/// Secondes Unix → FILETIME (100 ns depuis 1601).
fn filetime(unix_s: u64) -> u64 {
    (unix_s + 11_644_473_600) * 10_000_000
}

fn fill(info: &mut FileInfo, m: &Meta) {
    info.file_attributes = if m.is_dir {
        FILE_ATTRIBUTE_DIRECTORY
    } else {
        FILE_ATTRIBUTE_ARCHIVE
    };
    info.file_size = m.size;
    info.allocation_size = m.size.div_ceil(4096) * 4096;
    info.creation_time = filetime(m.created_at);
    info.last_write_time = filetime(m.modified_at);
    info.last_access_time = info.last_write_time;
    info.change_time = info.last_write_time;
    info.index_number = 0;
    info.hard_links = 0;
    info.reparse_tag = 0;
    info.ea_size = 0;
}

fn path_of(name: &U16CStr) -> String {
    name.to_string_lossy()
}

/// Signalement d'une écriture : `(chemin, taille)`.
pub type WriteHook = Arc<dyn Fn(&str, u64) + Send + Sync>;

/// Fichier ouvert.
pub struct Handle {
    path: Mutex<String>,
    is_dir: bool,
    dir: DirBuffer,
}

/// Contexte WinFsp : le moteur et le signalement des fichiers modifiés.
pub struct DriveFs {
    pub drive: Arc<Mutex<Drive>>,
    /// Appelé avec `(chemin, taille)` à chaque écriture (écriture différée).
    pub on_write: WriteHook,
    /// `(quota, occupé)` communiqué par le Nœud, s'il est connu.
    pub space: Arc<dyn Fn() -> Option<(u64, u64)> + Send + Sync>,
    /// Nœud injoignable : les fichiers absents de l'appareil sont refusés
    /// aussitôt (l'Explorateur Windows ne reste pas bloqué).
    pub offline: Arc<dyn Fn() -> bool + Send + Sync>,
}

impl DriveFs {
    fn stat(&self, path: &str) -> winfsp::Result<Meta> {
        self.drive
            .lock()
            .unwrap()
            .stat(path)
            .map_err(ntstatus)?
            .ok_or(FspError::NTSTATUS(STATUS_OBJECT_NAME_NOT_FOUND))
    }

    fn info(&self, h: &Handle, info: &mut FileInfo) -> winfsp::Result<()> {
        let m = self.stat(&h.path.lock().unwrap())?;
        fill(info, &m);
        Ok(())
    }
}

impl FileSystemContext for DriveFs {
    type FileContext = Handle;

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        security_descriptor: Option<&mut [c_void]>,
        _resolver: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> winfsp::Result<FileSecurity> {
        let m = self.stat(&path_of(file_name))?;
        if let Some(buf) = security_descriptor {
            if buf.len() >= SECURITY_DESCRIPTOR.len() {
                // SAFETY : `buf` est un tampon WinFsp d'au moins cette taille.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        SECURITY_DESCRIPTOR.as_ptr(),
                        buf.as_mut_ptr().cast::<u8>(),
                        SECURITY_DESCRIPTOR.len(),
                    );
                }
            }
        }
        Ok(FileSecurity {
            reparse: false,
            sz_security_descriptor: SECURITY_DESCRIPTOR.len() as u64,
            attributes: if m.is_dir {
                FILE_ATTRIBUTE_DIRECTORY
            } else {
                FILE_ATTRIBUTE_ARCHIVE
            },
        })
    }

    fn open(
        &self,
        file_name: &U16CStr,
        _create_options: u32,
        _granted_access: u32,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Handle> {
        let path = path_of(file_name);
        let m = self.stat(&path)?;
        fill(file_info.as_mut(), &m);
        Ok(Handle {
            path: Mutex::new(path),
            is_dir: m.is_dir,
            dir: DirBuffer::new(),
        })
    }

    fn close(&self, _context: Handle) {}

    fn create(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        _granted_access: u32,
        _file_attributes: u32,
        _security_descriptor: Option<&[c_void]>,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        _extra_buffer_is_reparse_point: bool,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Handle> {
        let path = path_of(file_name);
        let is_dir = create_options & FILE_DIRECTORY_FILE != 0;
        self.drive
            .lock()
            .unwrap()
            .create(&path, is_dir)
            .map_err(ntstatus)?;
        let m = self.stat(&path)?;
        fill(file_info.as_mut(), &m);
        Ok(Handle {
            path: Mutex::new(path),
            is_dir,
            dir: DirBuffer::new(),
        })
    }

    fn cleanup(&self, context: &Handle, _file_name: Option<&U16CStr>, flags: u32) {
        if flags & FSP_CLEANUP_DELETE != 0 {
            let path = context.path.lock().unwrap().clone();
            let _ = self.drive.lock().unwrap().remove(&path);
        }
    }

    fn flush(&self, context: Option<&Handle>, file_info: &mut FileInfo) -> winfsp::Result<()> {
        match context {
            Some(h) => self.info(h, file_info),
            None => Ok(()),
        }
    }

    fn get_file_info(&self, context: &Handle, file_info: &mut FileInfo) -> winfsp::Result<()> {
        self.info(context, file_info)
    }

    fn get_security(
        &self,
        _context: &Handle,
        security_descriptor: Option<&mut [c_void]>,
    ) -> winfsp::Result<u64> {
        if let Some(buf) = security_descriptor {
            if buf.len() >= SECURITY_DESCRIPTOR.len() {
                // SAFETY : voir `get_security_by_name`.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        SECURITY_DESCRIPTOR.as_ptr(),
                        buf.as_mut_ptr().cast::<u8>(),
                        SECURITY_DESCRIPTOR.len(),
                    );
                }
            }
        }
        Ok(SECURITY_DESCRIPTOR.len() as u64)
    }

    fn overwrite(
        &self,
        context: &Handle,
        _file_attributes: u32,
        _replace_file_attributes: bool,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        let path = context.path.lock().unwrap().clone();
        self.drive
            .lock()
            .unwrap()
            .set_size(&path, 0)
            .map_err(ntstatus)?;
        (self.on_write)(&path, 0);
        self.info(context, file_info)
    }

    fn read_directory(
        &self,
        context: &Handle,
        _pattern: Option<&U16CStr>,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        if !context.is_dir {
            return Err(FspError::NTSTATUS(STATUS_NOT_A_DIRECTORY));
        }
        if let Ok(lock) = context.dir.acquire(marker.is_none(), None) {
            let path = context.path.lock().unwrap().clone();
            let entries = self.drive.lock().unwrap().list(&path).map_err(ntstatus)?;
            let mut di: DirInfo = DirInfo::new();
            if path != "\\" && path != "/" {
                for dot in [".", ".."] {
                    di.reset();
                    fill(
                        di.file_info_mut(),
                        &Meta {
                            is_dir: true,
                            size: 0,
                            created_at: 0,
                            modified_at: 0,
                        },
                    );
                    di.set_name(dot)?;
                    lock.write(&mut di)?;
                }
            }
            for (name, m) in entries {
                di.reset();
                fill(di.file_info_mut(), &m);
                di.set_name(&name)?;
                lock.write(&mut di)?;
            }
        }
        Ok(context.dir.read(marker, buffer))
    }

    fn rename(
        &self,
        context: &Handle,
        file_name: &U16CStr,
        new_file_name: &U16CStr,
        replace_if_exists: bool,
    ) -> winfsp::Result<()> {
        let (from, to) = (path_of(file_name), path_of(new_file_name));
        self.drive
            .lock()
            .unwrap()
            .rename(&from, &to, replace_if_exists)
            .map_err(ntstatus)?;
        *context.path.lock().unwrap() = to.clone();
        (self.on_write)(&to, 0);
        Ok(())
    }

    fn set_basic_info(
        &self,
        context: &Handle,
        _file_attributes: u32,
        _creation_time: u64,
        _last_access_time: u64,
        _last_write_time: u64,
        _last_change_time: u64,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        self.info(context, file_info)
    }

    fn set_delete(
        &self,
        context: &Handle,
        _file_name: &U16CStr,
        delete_file: bool,
    ) -> winfsp::Result<()> {
        if delete_file && context.is_dir {
            let path = context.path.lock().unwrap().clone();
            let empty = self
                .drive
                .lock()
                .unwrap()
                .list(&path)
                .map_err(ntstatus)?
                .is_empty();
            if !empty {
                return Err(FspError::NTSTATUS(STATUS_DIRECTORY_NOT_EMPTY));
            }
        }
        Ok(())
    }

    fn set_file_size(
        &self,
        context: &Handle,
        new_size: u64,
        set_allocation_size: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        let path = context.path.lock().unwrap().clone();
        if !set_allocation_size {
            self.drive
                .lock()
                .unwrap()
                .set_size(&path, new_size)
                .map_err(ntstatus)?;
            (self.on_write)(&path, new_size);
        }
        self.info(context, file_info)
    }

    fn read(&self, context: &Handle, buffer: &mut [u8], offset: u64) -> winfsp::Result<u32> {
        let path = context.path.lock().unwrap().clone();
        let mut d = self.drive.lock().unwrap();
        let size = d
            .stat(&path)
            .map_err(ntstatus)?
            .map(|m| m.size)
            .unwrap_or(0);
        if offset >= size {
            return Err(FspError::NTSTATUS(STATUS_END_OF_FILE));
        }
        if (self.offline)() && !d.is_local(&path) {
            return Err(FspError::NTSTATUS(STATUS_FILE_IS_OFFLINE));
        }
        let data = d.read(&path, offset, buffer.len()).map_err(ntstatus)?;
        buffer[..data.len()].copy_from_slice(&data);
        Ok(data.len() as u32)
    }

    fn write(
        &self,
        context: &Handle,
        buffer: &[u8],
        offset: u64,
        write_to_eof: bool,
        constrained_io: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<u32> {
        let path = context.path.lock().unwrap().clone();
        let size = {
            let mut d = self.drive.lock().unwrap();
            let size = d
                .stat(&path)
                .map_err(ntstatus)?
                .map(|m| m.size)
                .unwrap_or(0);
            let offset = if write_to_eof { size } else { offset };
            let data = if constrained_io {
                if offset >= size {
                    return Ok(0);
                }
                &buffer[..buffer.len().min((size - offset) as usize)]
            } else {
                buffer
            };
            d.write(&path, offset, data).map_err(ntstatus)?;
            data.len()
        };
        let m = self.stat(&path)?;
        (self.on_write)(&path, m.size);
        fill(file_info, &m);
        Ok(size as u32)
    }

    fn get_volume_info(&self, out_volume_info: &mut VolumeInfo) -> winfsp::Result<()> {
        // Taille du lecteur = quota de l'Utilisateur (`RootState`) ;
        // inconnue tant que le Nœud ne l'a pas communiquée.
        let (total, used) = (self.space)().unwrap_or((1 << 40, 0));
        out_volume_info.total_size = total;
        out_volume_info.free_size = total.saturating_sub(used);
        out_volume_info.set_volume_label("S3m");
        Ok(())
    }
}

/// Monte le lecteur sur `mount_point` (ex. `P:`) ; le démontage a lieu à la
/// destruction de l'hôte rendu.
pub fn mount(fs: DriveFs, mount_point: &str) -> Result<FileSystemHost<DriveFs>, String> {
    // La DLL n'est pas dans le PATH par défaut : dossier d'installation
    // standard, ou `WINFSP_DIR` s'il est défini.
    let dir = std::env::var_os("WINFSP_DIR")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("ProgramFiles(x86)")
                .map(|p| std::path::PathBuf::from(p).join("WinFsp"))
        });
    let installed = dir
        .as_ref()
        .is_some_and(|d| d.join("bin").join("winfsp-x64.dll").exists());
    if let Some(bin) = dir.map(|d| d.join("bin")) {
        let mut paths = vec![bin];
        paths.extend(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        ));
        if let Ok(joined) = std::env::join_paths(paths) {
            std::env::set_var("PATH", joined);
        }
    }
    let _init = winfsp::winfsp_init().map_err(|e| {
        if installed {
            format!(
                "WinFsp est installé mais inutilisable ({e}) : redémarrez l'ordinateur, \
                 sinon réinstallez WinFsp avec un compte administrateur"
            )
        } else {
            "WinFsp n'est pas installé sur cet ordinateur : sans lui, le lecteur ne peut \
             pas être monté. Son installation demande une fois un compte administrateur \
             (winget install WinFsp.WinFsp, ou https://winfsp.dev), puis relancez S3m."
                .to_string()
        }
    })?;
    let mut params = VolumeParams::new();
    params
        .filesystem_name("S3m")
        .case_sensitive_search(true)
        .case_preserved_names(true)
        .unicode_on_disk(true)
        .persistent_acls(false)
        .post_cleanup_when_modified_only(true)
        .sector_size(4096)
        .sectors_per_allocation_unit(1)
        .max_component_length(255)
        .file_info_timeout(1000);
    let mut host =
        FileSystemHost::<DriveFs, FineGuard>::new(params, fs).map_err(|e| e.to_string())?;
    host.mount(mount_point).map_err(|e| e.to_string())?;
    host.start().map_err(|e| e.to_string())?;
    Ok(host)
}
