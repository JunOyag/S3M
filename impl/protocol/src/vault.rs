//! Coffre local des phrases secrètes (`deploiement.packaging#coffre-local`).
//!
//! Une phrase (`user.seed`, `node.seed`) est gardée :
//! - en clair (`<fichier>` lui-même, droits restreints) : mode historique ;
//! - dans le magasin du système (Gestionnaire d'identification Windows,
//!   Trousseau macOS) : `<fichier>.coffre` ne contient que la référence ;
//! - sous une phrase de passe : `<fichier>.coffre` contient la phrase
//!   chiffrée (Argon2id → ChaCha20-Poly1305). Le programme démarre alors
//!   verrouillé jusqu'à la saisie de la phrase de passe (localement, ou à
//!   distance pour un Nœud : clé de déverrouillage en clair, `unlock_key`).
//!
//! Le fichier en clair n'est supprimé qu'après relecture réussie du coffre.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Service du magasin du système.
pub const SERVICE: &str = "S3m";

/// Où est gardée une phrase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Storage {
    /// Fichier en clair.
    Plain,
    /// Magasin du système.
    System,
    /// Chiffrée sous une phrase de passe.
    Passphrase,
    /// Aucune phrase.
    Missing,
}

impl Storage {
    pub fn label(self) -> &'static str {
        match self {
            Storage::Plain => "fichier en clair",
            Storage::System => "coffre du système",
            Storage::Passphrase => "phrase de passe",
            Storage::Missing => "aucune",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("phrase verrouillée : phrase de passe nécessaire")]
    Locked,
    #[error("phrase de passe incorrecte")]
    BadPassphrase,
    #[error("coffre du système indisponible : {0}")]
    System(String),
    #[error("coffre illisible : {0}")]
    Format(String),
    #[error("E/S : {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Serialize, Deserialize, Default)]
struct VaultFile {
    v: u32,
    /// "systeme" ou "phrase".
    mode: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    compte: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    sel: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    nonce: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    chiffre: String,
    /// Clé de déverrouillage à distance (graine Ed25519 en clair) : identité
    /// libp2p du Nœud verrouillé, distincte de la sienne.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    deverrouillage: String,
}

/// Clés dérivées des phrases de passe saisies (réécriture sans redemande).
type Keys = HashMap<PathBuf, ([u8; 16], [u8; 32])>;
static KEYS: Mutex<Option<Keys>> = Mutex::new(None);

fn vault_path(seed: &Path) -> PathBuf {
    let mut p = seed.as_os_str().to_owned();
    p.push(".coffre");
    PathBuf::from(p)
}

/// Choix explicite du clair : plus de migration automatique.
fn plain_marker(seed: &Path) -> PathBuf {
    let mut p = seed.as_os_str().to_owned();
    p.push(".clair");
    PathBuf::from(p)
}

fn account(seed: &Path) -> String {
    let abs = std::fs::canonicalize(seed.parent().unwrap_or(Path::new(".")))
        .unwrap_or_else(|_| seed.to_path_buf())
        .join(seed.file_name().unwrap_or_default());
    let h = s3m_core::symmetric_suite::hash_sha256(abs.to_string_lossy().to_lowercase().as_bytes());
    format!("{}:{}", seed.file_name().unwrap_or_default().to_string_lossy(), hex::encode(&h[..8]))
}

fn load(seed: &Path) -> Result<Option<VaultFile>, VaultError> {
    match std::fs::read(vault_path(seed)) {
        Ok(b) => serde_json::from_slice(&b).map(Some).map_err(|e| VaultError::Format(e.to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn save(seed: &Path, v: &VaultFile) -> Result<(), VaultError> {
    let p = vault_path(seed);
    let tmp = p.with_extension("coffre.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(v).map_err(|e| VaultError::Format(e.to_string()))?)?;
    restrict(&tmp);
    std::fs::rename(&tmp, &p)?;
    Ok(())
}

/// Droits restreints au propriétaire (Unix : 0600).
pub fn restrict(p: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = p;
}

/// Où est gardée la phrase de `seed`.
pub fn storage(seed: &Path) -> Storage {
    match load(seed) {
        Ok(Some(v)) if v.mode == "systeme" => Storage::System,
        Ok(Some(_)) => Storage::Passphrase,
        _ if seed.exists() => Storage::Plain,
        _ => Storage::Missing,
    }
}

/// Le magasin du système est-il utilisable ici ?
pub fn system_available() -> bool {
    cfg!(any(windows, target_os = "macos"))
}

#[cfg(any(windows, target_os = "macos"))]
fn sys_entry(acc: &str) -> Result<keyring::Entry, VaultError> {
    keyring::Entry::new(SERVICE, acc).map_err(|e| VaultError::System(e.to_string()))
}

fn sys_get(acc: &str) -> Result<String, VaultError> {
    #[cfg(any(windows, target_os = "macos"))]
    return sys_entry(acc)?.get_password().map_err(|e| VaultError::System(e.to_string()));
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = acc;
        Err(VaultError::System("pas de magasin du système pris en charge".into()))
    }
}

fn sys_set(acc: &str, words: &str) -> Result<(), VaultError> {
    #[cfg(any(windows, target_os = "macos"))]
    return sys_entry(acc)?.set_password(words).map_err(|e| VaultError::System(e.to_string()));
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = (acc, words);
        Err(VaultError::System("pas de magasin du système pris en charge".into()))
    }
}

fn sys_delete(acc: &str) {
    #[cfg(any(windows, target_os = "macos"))]
    if let Ok(e) = sys_entry(acc) {
        let _ = e.delete_credential();
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    let _ = acc;
}

fn derive(pass: &str, salt: &[u8; 16]) -> Result<[u8; 32], VaultError> {
    let mut k = [0u8; 32];
    argon2::Argon2::default()
        .hash_password_into(pass.as_bytes(), salt, &mut k)
        .map_err(|e| VaultError::Format(e.to_string()))?;
    Ok(k)
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("CSPRNG du système");
    b
}

fn seal(key: &[u8; 32], words: &str) -> Result<(String, String), VaultError> {
    let nonce: [u8; 12] = random();
    let ct = ChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(Nonce::from_slice(&nonce), words.as_bytes())
        .map_err(|_| VaultError::Format("chiffrement".into()))?;
    Ok((hex::encode(nonce), hex::encode(ct)))
}

fn open(key: &[u8; 32], v: &VaultFile) -> Result<String, VaultError> {
    let f = |e: hex::FromHexError| VaultError::Format(e.to_string());
    let nonce = hex::decode(&v.nonce).map_err(f)?;
    let ct = hex::decode(&v.chiffre).map_err(f)?;
    if nonce.len() != 12 {
        return Err(VaultError::Format("nonce".into()));
    }
    let pt = Zeroizing::new(
        ChaCha20Poly1305::new(Key::from_slice(key))
            .decrypt(Nonce::from_slice(&nonce), ct.as_slice())
            .map_err(|_| VaultError::BadPassphrase)?,
    );
    String::from_utf8(pt.to_vec()).map_err(|e| VaultError::Format(e.to_string()))
}

fn remember(seed: &Path, salt: [u8; 16], key: [u8; 32]) {
    KEYS.lock().unwrap().get_or_insert_with(HashMap::new).insert(seed.to_path_buf(), (salt, key));
}

fn remembered(seed: &Path) -> Option<([u8; 16], [u8; 32])> {
    KEYS.lock().unwrap().as_ref()?.get(seed).copied()
}

/// Phrases transmises par le processus parent (redémarrage sans
/// redemander la phrase de passe).
static PROVIDED: Mutex<Option<HashMap<PathBuf, Zeroizing<String>>>> = Mutex::new(None);

/// Fournit la phrase déjà déverrouillée.
pub fn provide(seed: &Path, words: &str) {
    PROVIDED
        .lock()
        .unwrap()
        .get_or_insert_with(HashMap::new)
        .insert(seed.to_path_buf(), Zeroizing::new(words.trim().to_string()));
}

/// Lit la phrase ; `Locked` si une phrase de passe est nécessaire et n'a pas
/// encore été saisie dans ce processus.
pub fn read(seed: &Path) -> Result<String, VaultError> {
    match load(seed)? {
        None => Ok(std::fs::read_to_string(seed)?),
        Some(v) if v.mode == "systeme" => sys_get(&v.compte),
        Some(v) => match remembered(seed) {
            Some((_, key)) => open(&key, &v),
            None => PROVIDED
                .lock()
                .unwrap()
                .as_ref()
                .and_then(|m| m.get(seed))
                .map(|w| w.to_string())
                .ok_or(VaultError::Locked),
        },
    }
}

/// Déverrouille avec la phrase de passe (gardée dérivée en mémoire).
pub fn unlock(seed: &Path, pass: &str) -> Result<String, VaultError> {
    let v = load(seed)?.filter(|v| v.mode == "phrase").ok_or(VaultError::Format("pas de phrase de passe".into()))?;
    let salt: [u8; 16] = hex::decode(&v.sel)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(VaultError::Format("sel".into()))?;
    let key = derive(pass, &salt)?;
    let words = open(&key, &v)?;
    remember(seed, salt, key);
    Ok(words)
}

/// Efface le fichier en clair (réécrit avant suppression).
fn shred(p: &Path) {
    if let Ok(m) = std::fs::metadata(p) {
        let _ = std::fs::write(p, vec![0u8; m.len() as usize]);
    }
    let _ = std::fs::remove_file(p);
}

/// Range la phrase dans le magasin du système ; rend la main sans rien
/// changer si le magasin ne relit pas la même phrase.
pub fn protect_system(seed: &Path, words: &str) -> Result<(), VaultError> {
    let acc = account(seed);
    sys_set(&acc, words)?;
    if sys_get(&acc)?.trim() != words.trim() {
        return Err(VaultError::System("relecture différente".into()));
    }
    save(seed, &VaultFile { v: 1, mode: "systeme".into(), compte: acc, ..Default::default() })?;
    let _ = std::fs::remove_file(plain_marker(seed));
    shred(seed);
    Ok(())
}

/// Chiffre la phrase sous `pass` ; `with_unlock_key` crée la clé de
/// déverrouillage à distance (Nœud).
pub fn protect_passphrase(seed: &Path, words: &str, pass: &str, with_unlock_key: bool) -> Result<(), VaultError> {
    if pass.chars().count() < 8 {
        return Err(VaultError::Format("phrase de passe trop courte (8 caractères au moins)".into()));
    }
    let salt: [u8; 16] = random();
    let key = derive(pass, &salt)?;
    let (nonce, chiffre) = seal(&key, words)?;
    let old = load(seed)?;
    let deverrouillage = match &old {
        Some(o) if !o.deverrouillage.is_empty() => o.deverrouillage.clone(),
        _ if with_unlock_key => hex::encode(random::<32>()),
        _ => String::new(),
    };
    let v = VaultFile { v: 1, mode: "phrase".into(), sel: hex::encode(salt), nonce, chiffre, deverrouillage, ..Default::default() };
    if open(&key, &v)?.trim() != words.trim() {
        return Err(VaultError::Format("relecture différente".into()));
    }
    save(seed, &v)?;
    if let Some(o) = old.filter(|o| o.mode == "systeme") {
        sys_delete(&o.compte);
    }
    remember(seed, salt, key);
    let _ = std::fs::remove_file(plain_marker(seed));
    shred(seed);
    Ok(())
}

/// Remet la phrase en clair (export, retour au mode historique).
pub fn to_plain(seed: &Path, words: &str) -> Result<(), VaultError> {
    std::fs::write(seed, format!("{}\n", words.trim()))?;
    restrict(seed);
    if let Some(o) = load(seed)? {
        if o.mode == "systeme" {
            sys_delete(&o.compte);
        }
        std::fs::remove_file(vault_path(seed))?;
    }
    std::fs::write(plain_marker(seed), "phrase laissée en clair à la demande de l'utilisateur
")?;
    Ok(())
}

/// Remplace la phrase en gardant le mode de rangement (rotation
/// d'identité). Phrase de passe : la clé saisie dans ce processus sert.
pub fn write(seed: &Path, words: &str) -> Result<(), VaultError> {
    match load(seed)? {
        None => {
            std::fs::write(seed, format!("{}\n", words.trim()))?;
            restrict(seed);
            Ok(())
        }
        Some(v) if v.mode == "systeme" => sys_set(&v.compte, words),
        Some(mut v) => {
            let (salt, key) = remembered(seed).ok_or(VaultError::Locked)?;
            let (nonce, chiffre) = seal(&key, words)?;
            v.sel = hex::encode(salt);
            v.nonce = nonce;
            v.chiffre = chiffre;
            save(seed, &v)
        }
    }
}

/// Supprime la phrase où qu'elle soit (identité retirée).
pub fn remove(seed: &Path) {
    if let Ok(Some(o)) = load(seed) {
        if o.mode == "systeme" {
            sys_delete(&o.compte);
        }
        let _ = std::fs::remove_file(vault_path(seed));
    }
    let _ = std::fs::remove_file(plain_marker(seed));
    let _ = std::fs::remove_file(seed);
}

/// Migration au démarrage des exécutables : une phrase en clair passe dans
/// le magasin du système quand il existe. Rend le rangement final.
pub fn auto_protect(seed: &Path) -> Storage {
    if storage(seed) == Storage::Plain && system_available() && !plain_marker(seed).exists() {
        if let Ok(words) = std::fs::read_to_string(seed) {
            if let Err(e) = protect_system(seed, words.trim()) {
                eprintln!("coffre du système : {e} — phrase laissée en clair");
            }
        }
    }
    storage(seed)
}

/// Clé de déverrouillage à distance (graine Ed25519), si créée.
pub fn unlock_key(seed: &Path) -> Option<[u8; 32]> {
    hex::decode(load(seed).ok()??.deverrouillage).ok()?.try_into().ok()
}
