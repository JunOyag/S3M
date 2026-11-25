//! Gestion des volumes en service — id `protocols.gestion-volumes`.
//! Réf. spec : docs/04-protocols/gestion-volumes.md. Marqueur signé, import
//! d'un volume contenant déjà des blocs (intégrité, appartenance vérifiée
//! auprès des partenaires), effacement, vidage, brouillon de modifications.

use std::collections::HashSet;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use s3m_core::symmetric_suite::{canonical_encode, hash_sha256};
use s3m_protocol::exchange::{Body, Request, Response};
use serde::{Deserialize, Serialize};

use crate::chunk_store::{Id, Space};
use crate::dispersal_engine::{DispersalState, Fabric};
use crate::exchange::{unpack_bits, NodeService, MAX_OWNERSHIP_HASHES};
use crate::{OwnerType, PhysicalStore, StorageError, BITMAP_SIZE, BLOCK_SIZE, SLOT_COUNT};

/// Fichier marqueur à la racine d'un volume.
pub const MARKER_FILE: &str = "s3m-volume.json";
const MARKER_LABEL: &str = "s3m/sig/volume-marker/v1";
/// Blocs relus par lot pendant un import.
const IMPORT_BATCH: usize = 256;
/// Blocs déplacés par tour de vidage (verrou court).
pub const DRAIN_BATCH: usize = 64;

/// Marqueur `{node_id, volume_id, signature}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Marker {
    pub node_id: String,
    pub volume_id: u32,
    pub signature: String,
}

fn marker_message(node_id: &[u8; 32], volume_id: u32) -> Vec<u8> {
    let mut m = canonical_encode(&[MARKER_LABEL.as_bytes()]);
    m.extend_from_slice(node_id);
    m.extend_from_slice(&volume_id.to_be_bytes());
    m
}

/// Écrit le marqueur signé par `priv_node`.
pub fn write_marker(mount: &Path, priv_node: &[u8; 32], volume_id: u32) -> std::io::Result<()> {
    let key = SigningKey::from_bytes(priv_node);
    let node_id = key.verifying_key().to_bytes();
    let sig = key.sign(&marker_message(&node_id, volume_id));
    let m = Marker {
        node_id: hex::encode(node_id),
        volume_id,
        signature: hex::encode(sig.to_bytes()),
    };
    fs::create_dir_all(mount)?;
    fs::write(mount.join(MARKER_FILE), serde_json::to_vec_pretty(&m)?)
}

/// Marqueur présent et de signature valide.
pub fn read_marker(mount: &Path) -> Option<Marker> {
    let m: Marker = serde_json::from_slice(&fs::read(mount.join(MARKER_FILE)).ok()?).ok()?;
    let id: [u8; 32] = hex::decode(&m.node_id).ok()?.try_into().ok()?;
    let sig: [u8; 64] = hex::decode(&m.signature).ok()?.try_into().ok()?;
    VerifyingKey::from_bytes(&id)
        .ok()?
        .verify(
            &marker_message(&id, m.volume_id),
            &ed25519_dalek::Signature::from_bytes(&sig),
        )
        .ok()?;
    Some(m)
}

/// Ce que contient un chemin proposé comme volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inspection {
    /// Ni marqueur ni blocs.
    Empty,
    /// Volume de ce Nœud (marqueur valide).
    Mine { volume_id: u32, blocks: bool },
    /// Blocs sans marqueur.
    Unmarked,
    /// Marqueur d'un autre Nœud (ou illisible).
    Foreign { node_id: String },
}

/// `blocks/` ou `import-*/` non vides.
pub fn has_blocks(mount: &Path) -> bool {
    let non_empty = |p: PathBuf| fs::read_dir(p).is_ok_and(|mut d| d.next().is_some());
    non_empty(mount.join("blocks")) || !import_dirs(mount).is_empty()
}

pub fn inspect(mount: &Path, node_id: &[u8; 32]) -> Inspection {
    let marker_file = mount.join(MARKER_FILE).exists();
    match read_marker(mount) {
        Some(m) if m.node_id == hex::encode(node_id) => Inspection::Mine {
            volume_id: m.volume_id,
            blocks: has_blocks(mount),
        },
        Some(m) => Inspection::Foreign { node_id: m.node_id },
        None if marker_file => Inspection::Foreign {
            node_id: "marqueur illisible".into(),
        },
        None if has_blocks(mount) => Inspection::Unmarked,
        None => Inspection::Empty,
    }
}

/// Efface les données S3m d'un volume (jamais le disque lui-même).
pub fn wipe(mount: &Path) -> std::io::Result<()> {
    for d in import_dirs(mount).into_iter().chain([mount.join("blocks")]) {
        if d.exists() {
            fs::remove_dir_all(d)?;
        }
    }
    let m = mount.join(MARKER_FILE);
    if m.exists() {
        fs::remove_file(m)?;
    }
    Ok(())
}

/// Le chemin est-il un répertoire inscriptible ?
pub fn check_writable(mount: &Path) -> Result<(), String> {
    fs::create_dir_all(mount).map_err(|e| format!("{} : {e}", mount.display()))?;
    let probe = mount.join(".s3m-write-test");
    fs::write(&probe, b"ok").map_err(|e| format!("{} non inscriptible : {e}", mount.display()))?;
    let _ = fs::remove_file(probe);
    Ok(())
}

// ------------------------------------------------------------------ import

/// Répertoires `import-*` d'un volume.
pub fn import_dirs(mount: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = fs::read_dir(mount)
        .map(|d| {
            d.filter_map(|e| e.ok())
                .filter(|e| {
                    e.file_name().to_string_lossy().starts_with("import-") && e.path().is_dir()
                })
                .map(|e| e.path())
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

/// Met de côté les blocs trouvés (`blocks/` → `import-<horodatage>/`) :
/// aucune collision avec les conteneurs créés ensuite.
pub fn start_import(mount: &Path, stamp: u64) -> std::io::Result<Option<PathBuf>> {
    let b = mount.join("blocks");
    if !b.exists() {
        return Ok(None);
    }
    let dest = mount.join(format!("import-{stamp}"));
    fs::rename(&b, &dest)?;
    Ok(Some(dest))
}

/// Ouvre le stockage ; base absente ou illisible alors que des conteneurs
/// existent : base mise de côté (`store.sqlite.illisible-<instant>`),
/// conteneurs renommés pour être réimportés bloc par bloc (hash et
/// appartenance vérifiés, `protocols.gestion-volumes#import`). Rend le
/// stockage et, le cas échéant, le message à journaliser
/// (`protocols.stockage-physique#reconstruction-index`).
pub fn open_or_rebuild(
    db: &Path,
    volumes: Vec<crate::VolumeConfig>,
    now: u64,
) -> Result<(crate::PhysicalStore, Option<String>), crate::StorageError> {
    let had_db = db.exists();
    let reason = if had_db {
        match crate::PhysicalStore::open(db, volumes.clone()) {
            Ok(s) => return Ok((s, None)),
            Err(e) => {
                for ext in ["", "-wal", "-shm"] {
                    let p = PathBuf::from(format!("{}{ext}", db.display()));
                    if p.exists() {
                        let _ = fs::rename(&p, format!("{}.illisible-{now}{ext}", db.display()));
                    }
                }
                format!("base du stockage illisible ({e})")
            }
        }
    } else {
        "base du stockage absente".to_string()
    };
    let mut moved = 0;
    for v in &volumes {
        if v.mount_path.join("blocks").exists() && start_import(&v.mount_path, now)?.is_some() {
            moved += 1;
        }
    }
    let store = crate::PhysicalStore::open(db, volumes)?;
    let msg = (had_db || moved > 0).then(|| {
        format!("{reason} : mise de côté et index reconstruit en relisant les conteneurs de {moved} volume(s) (import en tâche de fond)")
    });
    Ok((store, msg))
}

/// Conteneur à importer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportFile {
    pub owner_type: OwnerType,
    pub owner_id: Vec<u8>,
    pub path: PathBuf,
}

/// Conteneurs `<dir>/<owner_type>/<owner_id>/container-*.bin`.
pub fn import_files(dir: &Path) -> Vec<ImportFile> {
    let mut out = Vec::new();
    let list = |p: &Path| -> Vec<PathBuf> {
        fs::read_dir(p)
            .map(|d| d.filter_map(|e| e.ok()).map(|e| e.path()).collect())
            .unwrap_or_default()
    };
    for t in list(dir) {
        let Some(ot) = t
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.parse::<u8>().ok())
            .and_then(|n| OwnerType::try_from(n).ok())
        else {
            continue;
        };
        for o in list(&t) {
            let Some(id) = o
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| hex::decode(n).ok())
            else {
                continue;
            };
            for f in list(&o) {
                if f.extension().is_some_and(|e| e == "bin") {
                    out.push(ImportFile {
                        owner_type: ot,
                        owner_id: id.clone(),
                        path: f,
                    });
                }
            }
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

/// Lot de slots relus : `(slot, contenu)` et slot suivant à lire.
pub type SlotBatch = (Vec<(u32, Vec<u8>)>, Option<u32>);

/// Relit au plus `max` slots occupés à partir de `from` : `(slot, contenu)`
/// et le slot suivant à lire (`None` : fin du conteneur).
pub fn read_slots(path: &Path, from: u32, max: usize) -> std::io::Result<SlotBatch> {
    let mut f = fs::File::open(path)?;
    let mut bitmap = vec![0u8; BITMAP_SIZE];
    f.read_exact(&mut bitmap)?;
    let mut out = Vec::new();
    let mut slot = from;
    while slot < SLOT_COUNT {
        if bitmap[(slot / 8) as usize] & (1 << (slot % 8)) != 0 {
            if out.len() == max {
                return Ok((out, Some(slot)));
            }
            let mut data = vec![0u8; BLOCK_SIZE];
            f.seek(SeekFrom::Start(
                BITMAP_SIZE as u64 + slot as u64 * BLOCK_SIZE as u64,
            ))?;
            if f.read_exact(&mut data).is_ok() {
                out.push((slot, data));
            }
        }
        slot += 1;
    }
    Ok((out, None))
}

/// Blocs d'un Utilisateur connus du registre de dispersion.
pub fn user_known(d: &DispersalState, user: &[u8]) -> HashSet<String> {
    let Some(u) = d.users.get(&hex::encode(user)) else {
        return HashSet::new();
    };
    u.pending
        .iter()
        .cloned()
        .chain(
            u.stripes
                .iter()
                .chain(u.index.iter())
                .flat_map(|s| s.data.iter().cloned()),
        )
        .collect()
}

/// Pour chaque hash : fragment placé chez `partner` et toujours tenu pour
/// sien (parité des stripes, de l'index, du snapshot, délai de grâce).
pub fn placed_with(d: &DispersalState, partner: &Id, hashes: &[Id]) -> Vec<bool> {
    let p = hex::encode(partner);
    let mut mine: HashSet<String> = HashSet::new();
    let mut add = |rec: &crate::dispersal_engine::StripeRec| {
        for (_, h, holder) in &rec.parity {
            if *holder == p {
                mine.insert(h.clone());
            }
        }
    };
    for u in d.users.values() {
        u.stripes.iter().chain(u.index.iter()).for_each(&mut add);
    }
    if let Some(s) = &d.snapshot.stripe {
        add(s);
    }
    let retired = d
        .users
        .values()
        .flat_map(|u| u.retired.iter())
        .chain(d.snapshot.retired.iter())
        .filter(|r| r.partner == p)
        .map(|r| r.hash.clone());
    mine.extend(retired);
    hashes
        .iter()
        .map(|h| mine.contains(&hex::encode(h)))
        .collect()
}

/// Bilan d'import d'un volume.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportCounts {
    pub kept: u64,
    pub already_present: u64,
    pub removed: u64,
    /// Partenaires injoignables : nouvel essai au tour suivant.
    pub waiting: Vec<String>,
    pub done: bool,
}

/// Un tour d'import des blocs mis de côté sur `mount`. Rend vrai quand tout
/// est traité. Un partenaire injoignable laisse son conteneur pour plus tard.
pub async fn import_step<F: Fabric + ?Sized>(
    service: &Arc<Mutex<NodeService>>,
    dispersal: &tokio::sync::Mutex<DispersalState>,
    fabric: &F,
    mount: &Path,
    counts: &mut ImportCounts,
) -> bool {
    counts.waiting.clear();
    for dir in import_dirs(mount) {
        for file in import_files(&dir) {
            if !import_file(service, dispersal, fabric, &file, counts).await {
                continue;
            }
            let _ = fs::remove_file(&file.path);
        }
        if import_files(&dir).is_empty() {
            let _ = fs::remove_dir_all(&dir);
        }
    }
    counts.done = import_dirs(mount).is_empty();
    counts.done
}

async fn import_file<F: Fabric + ?Sized>(
    service: &Arc<Mutex<NodeService>>,
    dispersal: &tokio::sync::Mutex<DispersalState>,
    fabric: &F,
    file: &ImportFile,
    counts: &mut ImportCounts,
) -> bool {
    let owner: Option<Id> = file.owner_id.clone().try_into().ok();
    let known = match (file.owner_type, owner) {
        (OwnerType::AttachedUser, Some(u)) if service.lock().unwrap().users.contains_key(&u) => {
            Some(user_known(&*dispersal.lock().await, &u))
        }
        _ => None,
    };
    let partner = match (file.owner_type, owner) {
        (OwnerType::Partner, Some(p)) if service.lock().unwrap().partners.contains_key(&p) => {
            Some(p)
        }
        _ => None,
    };
    let mut from = 0;
    loop {
        let Ok((slots, next)) = read_slots(&file.path, from, IMPORT_BATCH) else {
            return true;
        };
        let blocks: Vec<(Id, Vec<u8>)> = slots
            .into_iter()
            .map(|(_, d)| (hash_sha256(&d), d))
            .collect();
        let keep: Vec<bool> = match (file.owner_type, &known, partner) {
            (OwnerType::AttachedUser, Some(k), _) => blocks
                .iter()
                .map(|(h, _)| k.contains(&hex::encode(h)))
                .collect(),
            (OwnerType::Partner, _, Some(p)) => {
                let mut bits = Vec::with_capacity(blocks.len());
                for chunk in blocks.chunks(MAX_OWNERSHIP_HASHES) {
                    let hashes: Vec<u8> =
                        chunk.iter().flat_map(|(h, _)| h.iter().copied()).collect();
                    let req = Request {
                        credential: None,
                        body: Body::OwnershipQuery { hashes },
                    };
                    match fabric.request(&p, req).await {
                        Ok(Response::OwnershipAnswer { owned }) => {
                            bits.extend(unpack_bits(&owned, chunk.len()))
                        }
                        _ => {
                            counts.waiting.push(hex::encode(p));
                            return false;
                        }
                    }
                }
                bits
            }
            _ => vec![false; blocks.len()],
        };
        let space = if file.owner_type == OwnerType::Partner {
            Space::Fragment
        } else {
            Space::UserBlock
        };
        {
            let mut s = service.lock().unwrap();
            for ((h, data), k) in blocks.iter().zip(keep) {
                if !k {
                    counts.removed += 1;
                } else if s.store.contains(h) {
                    counts.already_present += 1;
                } else if s
                    .store
                    .put(space, owner.as_ref().expect("propriétaire"), h, data)
                    .is_ok()
                {
                    counts.kept += 1;
                } else {
                    counts.removed += 1;
                }
            }
        }
        match next {
            Some(n) => from = n,
            None => return true,
        }
    }
}

// ------------------------------------------------------------------ vidage

/// Un tour de vidage : déplace au plus `max` blocs ; rend le nombre restant
/// (0 : volume vide).
pub fn drain_step(
    store: &mut PhysicalStore,
    volume_id: u32,
    max: usize,
) -> Result<usize, StorageError> {
    for h in store.blocks_on_volume(volume_id, max)? {
        store.relocate_block(&h)?;
    }
    Ok(store.blocks_on_volume(volume_id, 1)?.len())
}

// ------------------------------------------------------------- brouillon

/// Modification de volume saisie dans le brouillon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Change {
    Add {
        path: String,
        capacity_bytes: u64,
        wipe: bool,
    },
    Edit {
        volume_id: u32,
        path: Option<String>,
        capacity_bytes: Option<u64>,
    },
    Remove {
        volume_id: u32,
    },
    CancelRemove {
        volume_id: u32,
    },
    Lost {
        volume_id: u32,
    },
    Wipe {
        volume_id: u32,
    },
}

fn gib(b: u64) -> String {
    format!("{:.1} Go", b as f64 / (1u64 << 30) as f64).replace('.', ",")
}

impl Change {
    /// Volume concerné (aucun pour un ajout).
    pub fn volume(&self) -> Option<u32> {
        match self {
            Change::Add { .. } => None,
            Change::Edit { volume_id, .. }
            | Change::Remove { volume_id }
            | Change::CancelRemove { volume_id }
            | Change::Lost { volume_id }
            | Change::Wipe { volume_id } => Some(*volume_id),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Change::Add {
                path,
                capacity_bytes,
                wipe,
            } => format!(
                "ajouter {path} ({}){}",
                gib(*capacity_bytes),
                if *wipe {
                    ", en effaçant ses données S3m"
                } else {
                    ""
                }
            ),
            Change::Edit {
                volume_id,
                path,
                capacity_bytes,
            } => {
                let mut parts = Vec::new();
                if let Some(p) = path {
                    parts.push(format!("chemin {p}"));
                }
                if let Some(c) = capacity_bytes {
                    parts.push(format!("capacité {}", gib(*c)));
                }
                format!("modifier le volume {volume_id} : {}", parts.join(", "))
            }
            Change::Remove { volume_id } => {
                format!("retirer le volume {volume_id} (vidage vers les autres volumes)")
            }
            Change::CancelRemove { volume_id } => {
                format!("annuler le retrait du volume {volume_id}")
            }
            Change::Lost { volume_id } => format!(
                "déclarer perdu le volume {volume_id} (reconstruction depuis les partenaires)"
            ),
            Change::Wipe { volume_id } => format!("effacer et retirer le volume vide {volume_id}"),
        }
    }
}

/// Valide le brouillon entier avant toute exécution (`§ Brouillon`).
pub fn validate(
    changes: &[Change],
    usage: &[crate::VolumeUsage],
    node_id: &[u8; 32],
) -> Result<(), String> {
    let find = |id: u32| {
        usage
            .iter()
            .find(|u| u.volume_id == id)
            .ok_or(format!("volume {id} inconnu"))
    };
    let mut seen = HashSet::new();
    let mut paths: Vec<String> = usage
        .iter()
        .map(|u| u.mount_path.display().to_string())
        .collect();
    // Volumes actifs après le brouillon : (identifiant ou ajout, place libre).
    let mut active: Vec<(Option<u32>, u64)> = usage
        .iter()
        .filter(|u| !u.draining)
        .map(|u| {
            (
                Some(u.volume_id),
                u.max_capacity_bytes.saturating_sub(u.used_bytes),
            )
        })
        .collect();
    let mut to_evacuate: u64 = 0;
    for c in changes {
        if let Some(id) = c.volume() {
            if !seen.insert(id) {
                return Err(format!("plusieurs modifications pour le volume {id}"));
            }
        }
        match c {
            Change::Add {
                path,
                capacity_bytes,
                wipe,
            } => {
                let p = path.trim();
                if p.is_empty() || *capacity_bytes == 0 {
                    return Err("ajout : chemin et capacité requis".into());
                }
                if paths.iter().any(|x| Path::new(x) == Path::new(p)) {
                    return Err(format!("{p} est déjà un volume"));
                }
                paths.push(p.to_string());
                check_writable(Path::new(p))?;
                if let Inspection::Foreign { node_id: other } = inspect(Path::new(p), node_id) {
                    if !wipe {
                        return Err(format!(
                            "{p} est un disque d'un autre Nœud ({other}) : cochez « effacer et réutiliser » pour l'employer"
                        ));
                    }
                }
                active.push((None, *capacity_bytes));
            }
            Change::Edit {
                volume_id,
                path,
                capacity_bytes,
            } => {
                let u = find(*volume_id)?;
                if let Some(cap) = capacity_bytes {
                    if *cap < u.used_bytes {
                        return Err(format!(
                            "volume {volume_id} : capacité inférieure à l'occupation ({})",
                            gib(u.used_bytes)
                        ));
                    }
                    if let Some(a) = active.iter_mut().find(|a| a.0 == Some(*volume_id)) {
                        a.1 = cap - u.used_bytes;
                    }
                }
                if let Some(p) = path {
                    if u.used_bytes > 0 && !Path::new(p).join("blocks").exists() {
                        return Err(format!("volume {volume_id} : les données ne sont pas dans {p} (déplacez-les d'abord)"));
                    }
                }
            }
            Change::Remove { volume_id } => {
                let u = find(*volume_id)?;
                if u.draining {
                    return Err(format!("le volume {volume_id} est déjà en vidage"));
                }
                active.retain(|a| a.0 != Some(*volume_id));
                to_evacuate += u.used_bytes;
            }
            Change::CancelRemove { volume_id } => {
                let u = find(*volume_id)?;
                if !u.draining {
                    return Err(format!("le volume {volume_id} n'est pas en vidage"));
                }
                active.push((
                    Some(*volume_id),
                    u.max_capacity_bytes.saturating_sub(u.used_bytes),
                ));
            }
            Change::Lost { volume_id } => {
                find(*volume_id)?;
                active.retain(|a| a.0 != Some(*volume_id));
            }
            Change::Wipe { volume_id } => {
                if find(*volume_id)?.blocks > 0 {
                    return Err(format!(
                        "le volume {volume_id} contient des blocs : retirez-le d'abord"
                    ));
                }
                active.retain(|a| a.0 != Some(*volume_id));
            }
        }
    }
    if active.is_empty() {
        return Err("il doit rester au moins un volume actif".into());
    }
    let free: u64 = active.iter().map(|a| a.1).sum();
    if to_evacuate > free {
        return Err(format!(
            "place insuffisante sur les autres volumes : {} à déplacer, {} libres",
            gib(to_evacuate),
            gib(free)
        ));
    }
    Ok(())
}
