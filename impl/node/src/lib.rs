//! Physical block storage for the node component.
//!
//! The SQLite database is the durable local index: mutations to container
//! metadata and BlockLocation rows are committed together in WAL mode. The
//! append-only mutation log is compacted into a SQLite snapshot at the same
//! thresholds used by the NodeManifest mutation cycle.

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
#[cfg(windows)]
use std::ffi::c_void;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub const BLOCK_SIZE: usize = 65_536;
pub const BITMAP_SIZE: usize = 8_192;
pub const SLOT_COUNT: u32 = 65_536;
pub const SLOT_BYTES: u64 = 4 * 1024 * 1024 * 1024;
pub const CONTAINER_FILE_BYTES: u64 = SLOT_BYTES + BITMAP_SIZE as u64;
const LOG_COMPACTION_BYTES: u64 = 1024 * 1024;
const LOG_COMPACTION_INTERVAL_SECS: u64 = 60 * 60;

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn DeviceIoControl(
        device: *mut c_void,
        control_code: u32,
        input: *const c_void,
        input_size: u32,
        output: *mut c_void,
        output_size: u32,
        bytes_returned: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("snapshot serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("invalid owner type {0}; expected 0, 1, or 2")]
    InvalidOwnerType(u8),
    #[error("owner_id and block_hash must not be empty")]
    EmptyIdentity,
    #[error("a block must be exactly {BLOCK_SIZE} bytes, got {0}")]
    InvalidBlockSize(usize),
    #[error("container {0} references a volume not configured at startup")]
    MissingVolume(u32),
    #[error("no configured volume has free capacity for a new container")]
    NoVolumeCapacity,
    #[error("container metadata is invalid: {0}")]
    InvalidContainer(String),
    #[error("block hash already belongs to a different owner")]
    OwnerMismatch,
    #[error("replacement block hash already exists")]
    DuplicateBlockHash,
    #[error("the requested block location is not occupied")]
    MissingBlock,
    #[error("container identifier or owner sequence number overflow")]
    IdentifierOverflow,
    #[error("container file {0} is missing although its bitmap has occupied slots")]
    MissingOccupiedContainer(PathBuf),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum OwnerType {
    AttachedUser = 0,
    Partner = 1,
    EmergencyDepositor = 2,
}

impl TryFrom<u8> for OwnerType {
    type Error = StorageError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::AttachedUser),
            1 => Ok(Self::Partner),
            2 => Ok(Self::EmergencyDepositor),
            other => Err(StorageError::InvalidOwnerType(other)),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct Owner {
    pub owner_type: OwnerType,
    pub owner_id: Vec<u8>,
}

impl Owner {
    pub fn new(owner_type: OwnerType, owner_id: impl Into<Vec<u8>>) -> Result<Self, StorageError> {
        let owner_id = owner_id.into();
        if owner_id.is_empty() {
            return Err(StorageError::EmptyIdentity);
        }
        Ok(Self {
            owner_type,
            owner_id,
        })
    }
}

#[derive(Clone, Debug)]
pub struct VolumeConfig {
    pub volume_id: u32,
    pub mount_path: PathBuf,
    pub max_capacity_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerFile {
    pub container_id: u32,
    pub volume_id: u32,
    pub owner_type: OwnerType,
    pub owner_id: Vec<u8>,
    pub sequence_number: u32,
    pub slot_count: u32,
    pub occupied_bitmap: Vec<u8>,
    /// Relative to the mount path belonging to `volume_id`.
    pub file_path: String,
    pub created_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlockLocation {
    pub block_hash: Vec<u8>,
    pub container_id: u32,
    pub slot_index: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
enum Mutation {
    Put {
        container: ContainerFile,
        location: BlockLocation,
    },
    Replace {
        container: ContainerFile,
        old_hash: Vec<u8>,
        location: BlockLocation,
    },
    Remove {
        container_id: u32,
        slot_index: u32,
        block_hash: Vec<u8>,
        removed_container: bool,
    },
    RemoveOwner {
        owner: Owner,
    },
}

#[derive(Serialize, Deserialize)]
struct Snapshot {
    containers: Vec<ContainerFile>,
    locations: Vec<BlockLocation>,
    last_mutation_id: i64,
    created_at: u64,
}

/// Node-local physical block storage.
pub struct PhysicalStore {
    connection: Connection,
    volumes: BTreeMap<u32, VolumeConfig>,
    /// In-memory bitmap cache, reconstructed from SQLite on startup.
    containers_cache: HashMap<u32, ContainerFile>,
}

impl PhysicalStore {
    /// Open/create the local SQLite database and reconcile persisted bitmap
    /// headers from its durable metadata. The actual block data remains in
    /// sparse volume files and is not duplicated into SQLite.
    pub fn open(
        database_path: impl AsRef<Path>,
        volumes: Vec<VolumeConfig>,
    ) -> Result<Self, StorageError> {
        let mut volume_map = BTreeMap::new();
        for volume in volumes {
            fs::create_dir_all(&volume.mount_path)?;
            if volume_map.insert(volume.volume_id, volume).is_some() {
                return Err(StorageError::InvalidContainer(
                    "duplicate volume_id in configuration".to_owned(),
                ));
            }
        }
        let database_path = database_path.as_ref();
        if let Some(parent) = database_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let connection = Connection::open(database_path)?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS containers (
                 container_id INTEGER PRIMARY KEY,
                 volume_id INTEGER NOT NULL,
                 owner_type INTEGER NOT NULL,
                 owner_id BLOB NOT NULL,
                 sequence_number INTEGER NOT NULL,
                 slot_count INTEGER NOT NULL,
                 occupied_bitmap BLOB NOT NULL,
                 file_path TEXT NOT NULL,
                 created_at INTEGER NOT NULL,
                 UNIQUE(owner_type, owner_id, sequence_number)
             );
             CREATE TABLE IF NOT EXISTS block_locations (
                 block_hash BLOB PRIMARY KEY,
                 container_id INTEGER NOT NULL REFERENCES containers(container_id)
                     ON DELETE CASCADE,
                 slot_index INTEGER NOT NULL,
                 UNIQUE(container_id, slot_index)
             );
             CREATE TABLE IF NOT EXISTS mutation_log (
                 mutation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                 created_at INTEGER NOT NULL,
                 payload BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS mutation_snapshot (
                 singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                 created_at INTEGER NOT NULL,
                 last_mutation_id INTEGER NOT NULL,
                 payload BLOB NOT NULL
             );",
        )?;
        let containers_cache = load_all_containers(&connection)?
            .into_iter()
            .map(|container| (container.container_id, container))
            .collect();
        let store = Self {
            connection,
            volumes: volume_map,
            containers_cache,
        };
        store.restore_container_files()?;
        store.validate_location_bitmaps()?;
        Ok(store)
    }

    /// Store a block in its owner's first free slot, ordered by
    /// (sequence_number, slot_index). An existing hash is rewritten in place.
    pub fn write_block(
        &mut self,
        owner: &Owner,
        block_hash: &[u8],
        block: &[u8],
    ) -> Result<BlockLocation, StorageError> {
        Self::validate_identity(owner, block_hash)?;
        Self::validate_block(block)?;
        if let Some(existing) = self.location(block_hash)? {
            let container = self.container(existing.container_id)?;
            if container.owner_type != owner.owner_type || container.owner_id != owner.owner_id {
                return Err(StorageError::OwnerMismatch);
            }
            self.write_at(&container, existing.slot_index, block)?;
            self.persist_mutation(
                Mutation::Replace {
                    container,
                    old_hash: block_hash.to_vec(),
                    location: existing.clone(),
                },
                |_| Ok(()),
            )?;
            self.maybe_compact_mutation_log()?;
            return Ok(existing);
        }

        let containers = self.containers_for(owner)?;
        if let Some((container_id, slot)) = first_available_slot(&containers) {
            let mut container = containers
                .into_iter()
                .find(|container| container.container_id == container_id)
                .expect("allocator only returns a listed container");
            let location = BlockLocation {
                block_hash: block_hash.to_vec(),
                container_id: container.container_id,
                slot_index: slot,
            };
            set_slot(&mut container.occupied_bitmap, slot, true);
            self.write_at(&container, slot, block)?;
            self.persist_mutation(
                Mutation::Put {
                    container: container.clone(),
                    location: location.clone(),
                },
                |tx| {
                    persist_container(tx, &container)?;
                    tx.execute(
                        "INSERT INTO block_locations(block_hash, container_id, slot_index)
                             VALUES (?1, ?2, ?3)",
                        params![block_hash, location.container_id, location.slot_index],
                    )?;
                    Ok(())
                },
            )?;
            self.containers_cache
                .insert(container.container_id, container.clone());
            self.write_bitmap_header(location.container_id)?;
            self.maybe_compact_mutation_log()?;
            return Ok(location);
        }

        let mut container = self.create_container(owner)?;
        let location = BlockLocation {
            block_hash: block_hash.to_vec(),
            container_id: container.container_id,
            slot_index: 0,
        };
        set_slot(&mut container.occupied_bitmap, 0, true);
        self.write_at(&container, 0, block)?;
        self.persist_mutation(
            Mutation::Put {
                container: container.clone(),
                location: location.clone(),
            },
            |tx| {
                persist_container(tx, &container)?;
                tx.execute(
                    "INSERT INTO block_locations(block_hash, container_id, slot_index)
                     VALUES (?1, ?2, ?3)",
                    params![block_hash, location.container_id, location.slot_index],
                )?;
                Ok(())
            },
        )?;
        self.containers_cache
            .insert(container.container_id, container.clone());
        self.write_bitmap_header(location.container_id)?;
        self.maybe_compact_mutation_log()?;
        Ok(location)
    }

    /// Replace a padding (or other old block) with the real block without
    /// changing its physical `(container_id, slot_index)`.
    pub fn replace_block(
        &mut self,
        owner: &Owner,
        old_hash: &[u8],
        new_hash: &[u8],
        block: &[u8],
    ) -> Result<BlockLocation, StorageError> {
        Self::validate_identity(owner, old_hash)?;
        Self::validate_identity(owner, new_hash)?;
        Self::validate_block(block)?;
        let old_location = self.location(old_hash)?.ok_or(StorageError::MissingBlock)?;
        let container = self.container(old_location.container_id)?;
        if container.owner_type != owner.owner_type || container.owner_id != owner.owner_id {
            return Err(StorageError::OwnerMismatch);
        }
        if old_hash != new_hash && self.location(new_hash)?.is_some() {
            return Err(StorageError::DuplicateBlockHash);
        }
        let new_location = BlockLocation {
            block_hash: new_hash.to_vec(),
            container_id: old_location.container_id,
            slot_index: old_location.slot_index,
        };
        self.write_at(&container, old_location.slot_index, block)?;
        if old_hash != new_hash {
            self.persist_mutation(
                Mutation::Replace {
                    container: container.clone(),
                    old_hash: old_hash.to_vec(),
                    location: new_location.clone(),
                },
                |tx| {
                    tx.execute(
                        "DELETE FROM block_locations WHERE block_hash = ?1",
                        params![old_hash],
                    )?;
                    tx.execute(
                        "INSERT INTO block_locations(block_hash, container_id, slot_index)
                         VALUES (?1, ?2, ?3)",
                        params![new_hash, new_location.container_id, new_location.slot_index],
                    )?;
                    Ok(())
                },
            )?;
            self.maybe_compact_mutation_log()?;
        } else {
            // Same hash means the location is unchanged. Record a mutation
            // because the opaque ciphertext content has changed in place.
            self.persist_mutation(
                Mutation::Replace {
                    container: container.clone(),
                    old_hash: old_hash.to_vec(),
                    location: new_location.clone(),
                },
                |_| Ok(()),
            )?;
            self.maybe_compact_mutation_log()?;
        }
        Ok(new_location)
    }

    /// Remove a block, clear its bit, punch the slot when the platform
    /// supports hole-punching, and delete an entirely empty container.
    pub fn remove_block(&mut self, block_hash: &[u8]) -> Result<bool, StorageError> {
        if block_hash.is_empty() {
            return Err(StorageError::EmptyIdentity);
        }
        let Some(location) = self.location(block_hash)? else {
            return Ok(false);
        };
        let mut container = self.container(location.container_id)?;
        if !slot_is_set(&container.occupied_bitmap, location.slot_index) {
            return Err(StorageError::InvalidContainer(
                "BlockLocation points to a free slot".to_owned(),
            ));
        }
        set_slot(&mut container.occupied_bitmap, location.slot_index, false);
        let remove_container = container.occupied_bitmap.iter().all(|byte| *byte == 0);
        let path = self.absolute_path(&container)?;
        self.persist_mutation(
            Mutation::Remove {
                container_id: location.container_id,
                slot_index: location.slot_index,
                block_hash: block_hash.to_vec(),
                removed_container: remove_container,
            },
            |tx| {
                tx.execute(
                    "DELETE FROM block_locations WHERE block_hash = ?1",
                    params![block_hash],
                )?;
                if remove_container {
                    tx.execute(
                        "DELETE FROM containers WHERE container_id = ?1",
                        params![location.container_id],
                    )?;
                } else {
                    persist_container(tx, &container)?;
                }
                Ok(())
            },
        )?;
        if remove_container {
            self.containers_cache.remove(&location.container_id);
            if path.exists() {
                fs::remove_file(path)?;
            }
        } else {
            self.containers_cache
                .insert(container.container_id, container.clone());
            self.write_bitmap_header(location.container_id)?;
            punch_hole(&path, slot_offset(location.slot_index), BLOCK_SIZE as u64)?;
        }
        self.maybe_compact_mutation_log()?;
        Ok(true)
    }

    /// Remove every container belonging to one logical owner, regardless of
    /// volume, and cascade-delete its local BlockLocation rows.
    pub fn remove_owner(&mut self, owner: &Owner) -> Result<usize, StorageError> {
        if owner.owner_id.is_empty() {
            return Err(StorageError::EmptyIdentity);
        }
        let containers = self.containers_for(owner)?;
        let paths = containers
            .iter()
            .map(|container| self.absolute_path(container))
            .collect::<Result<Vec<_>, _>>()?;
        self.persist_mutation(
            Mutation::RemoveOwner {
                owner: owner.clone(),
            },
            |tx| {
                tx.execute(
                    "DELETE FROM containers WHERE owner_type = ?1 AND owner_id = ?2",
                    params![owner.owner_type as u8, owner.owner_id],
                )?;
                Ok(())
            },
        )?;
        for container in &containers {
            self.containers_cache.remove(&container.container_id);
        }
        for path in paths {
            if path.exists() {
                fs::remove_file(path)?;
            }
        }
        self.maybe_compact_mutation_log()?;
        Ok(containers.len())
    }

    pub fn location(&self, block_hash: &[u8]) -> Result<Option<BlockLocation>, StorageError> {
        self.connection
            .query_row(
                "SELECT block_hash, container_id, slot_index
                 FROM block_locations WHERE block_hash = ?1",
                params![block_hash],
                |row| {
                    Ok(BlockLocation {
                        block_hash: row.get(0)?,
                        container_id: row.get(1)?,
                        slot_index: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(StorageError::from)
    }

    pub fn read_block(&self, block_hash: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let Some(location) = self.location(block_hash)? else {
            return Ok(None);
        };
        let container = self.container(location.container_id)?;
        let path = self.absolute_path(&container)?;
        let mut file = File::open(path)?;
        file.seek(SeekFrom::Start(slot_offset(location.slot_index)))?;
        let mut bytes = vec![0; BLOCK_SIZE];
        file.read_exact(&mut bytes)?;
        Ok(Some(bytes))
    }

    pub fn containers(&self, owner: &Owner) -> Result<Vec<ContainerFile>, StorageError> {
        self.containers_for(owner)
    }

    pub fn container(&self, container_id: u32) -> Result<ContainerFile, StorageError> {
        if let Some(container) = self.containers_cache.get(&container_id) {
            return Ok(container.clone());
        }
        self.connection
            .query_row(
                "SELECT container_id, volume_id, owner_type, owner_id, sequence_number,
                        slot_count, occupied_bitmap, file_path, created_at
                 FROM containers WHERE container_id = ?1",
                params![container_id],
                container_from_row,
            )
            .optional()?
            .ok_or_else(|| {
                StorageError::InvalidContainer(format!("unknown container id {container_id}"))
            })
    }

    /// Force a snapshot now. This compacts the append-only mutation table but
    /// never moves blocks between physical containers.
    pub fn compact_mutation_log(&mut self) -> Result<(), StorageError> {
        let tx = self.connection.transaction()?;
        let containers = load_all_containers(&tx)?;
        let locations = load_all_locations(&tx)?;
        let last_mutation_id: i64 = tx.query_row(
            "SELECT COALESCE(MAX(mutation_id), 0) FROM mutation_log",
            [],
            |row| row.get(0),
        )?;
        let snapshot = Snapshot {
            containers,
            locations,
            last_mutation_id,
            created_at: now_seconds(),
        };
        let payload = serde_json::to_vec(&snapshot)?;
        tx.execute(
            "INSERT INTO mutation_snapshot(singleton, created_at, last_mutation_id, payload)
             VALUES (1, ?1, ?2, ?3)
             ON CONFLICT(singleton) DO UPDATE SET
                 created_at = excluded.created_at,
                 last_mutation_id = excluded.last_mutation_id,
                 payload = excluded.payload",
            params![snapshot.created_at, last_mutation_id, payload],
        )?;
        tx.execute(
            "DELETE FROM mutation_log WHERE mutation_id <= ?1",
            params![last_mutation_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn maybe_compact_mutation_log(&mut self) -> Result<(), StorageError> {
        let (bytes, last_snapshot): (i64, Option<i64>) = self.connection.query_row(
            "SELECT (SELECT COALESCE(SUM(length(payload)), 0) FROM mutation_log),
                    (SELECT created_at FROM mutation_snapshot WHERE singleton = 1)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let hourly_due = last_snapshot
            .map(|timestamp| {
                now_seconds().saturating_sub(timestamp as u64) >= LOG_COMPACTION_INTERVAL_SECS
            })
            .unwrap_or(true);
        if bytes as u64 >= LOG_COMPACTION_BYTES || hourly_due {
            self.compact_mutation_log()?;
        }
        Ok(())
    }

    fn persist_mutation<F>(&mut self, mutation: Mutation, apply: F) -> Result<(), StorageError>
    where
        F: FnOnce(&Transaction<'_>) -> Result<(), rusqlite::Error>,
    {
        let payload = serde_json::to_vec(&mutation)?;
        let tx = self.connection.transaction()?;
        tx.execute(
            "INSERT INTO mutation_log(created_at, payload) VALUES (?1, ?2)",
            params![now_seconds(), payload],
        )?;
        apply(&tx)?;
        tx.commit()?;
        Ok(())
    }

    fn create_container(&self, owner: &Owner) -> Result<ContainerFile, StorageError> {
        let existing = self.containers_for(owner)?;
        let sequence_number = existing
            .iter()
            .map(|container| container.sequence_number)
            .max()
            .map(|max| max.checked_add(1).ok_or(StorageError::IdentifierOverflow))
            .transpose()?
            .unwrap_or(0);
        let container_id = self.connection.query_row(
            "SELECT COALESCE(MAX(container_id), -1) + 1 FROM containers",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        let container_id =
            u32::try_from(container_id).map_err(|_| StorageError::IdentifierOverflow)?;
        let volume = self.least_loaded_volume()?;
        let relative_path = PathBuf::from("blocks")
            .join((owner.owner_type as u8).to_string())
            .join(hex(&owner.owner_id))
            .join(format!("container-{sequence_number}.bin"));
        let file_path = path_to_slashes(&relative_path);
        let container = ContainerFile {
            container_id,
            volume_id: volume.volume_id,
            owner_type: owner.owner_type,
            owner_id: owner.owner_id.clone(),
            sequence_number,
            slot_count: SLOT_COUNT,
            occupied_bitmap: vec![0; BITMAP_SIZE],
            file_path,
            created_at: now_seconds(),
        };
        let absolute = volume.mount_path.join(relative_path);
        if let Some(parent) = absolute.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&absolute)?;
        mark_sparse(&file)?;
        file.set_len(CONTAINER_FILE_BYTES)?;
        file.sync_all()?;
        write_header(&absolute, &container.occupied_bitmap)?;
        Ok(container)
    }

    fn least_loaded_volume(&self) -> Result<&VolumeConfig, StorageError> {
        let mut selected: Option<(&VolumeConfig, u64)> = None;
        for volume in self.volumes.values() {
            let used = self.physical_usage(volume.volume_id)?;
            let free = volume.max_capacity_bytes.saturating_sub(used);
            if free == 0 {
                continue;
            }
            if selected
                .map(|(best_volume, best)| {
                    free > best || (free == best && volume.volume_id < best_volume.volume_id)
                })
                .unwrap_or(true)
            {
                selected = Some((volume, free));
            }
        }
        selected
            .map(|(volume, _)| volume)
            .ok_or(StorageError::NoVolumeCapacity)
    }

    fn physical_usage(&self, volume_id: u32) -> Result<u64, StorageError> {
        let volume = self
            .volumes
            .get(&volume_id)
            .ok_or(StorageError::MissingVolume(volume_id))?;
        let mut used = 0u64;
        for container in self
            .containers_cache
            .values()
            .filter(|container| container.volume_id == volume_id)
        {
            let path = volume.mount_path.join(Path::new(&container.file_path));
            if let Ok(metadata) = fs::metadata(&path) {
                used = used.saturating_add(allocated_bytes(&metadata).unwrap_or_else(|| {
                    BITMAP_SIZE as u64
                        + occupied_count(&container.occupied_bitmap) as u64 * BLOCK_SIZE as u64
                }));
            } else {
                used = used.saturating_add(
                    BITMAP_SIZE as u64
                        + occupied_count(&container.occupied_bitmap) as u64 * BLOCK_SIZE as u64,
                );
            }
        }
        Ok(used)
    }

    fn containers_for(&self, owner: &Owner) -> Result<Vec<ContainerFile>, StorageError> {
        let mut containers = self
            .containers_cache
            .values()
            .filter(|container| {
                container.owner_type == owner.owner_type && container.owner_id == owner.owner_id
            })
            .cloned()
            .collect::<Vec<_>>();
        containers.sort_by_key(|container| container.sequence_number);
        for container in &containers {
            validate_container(container)?;
        }
        Ok(containers)
    }

    fn absolute_path(&self, container: &ContainerFile) -> Result<PathBuf, StorageError> {
        let volume = self
            .volumes
            .get(&container.volume_id)
            .ok_or(StorageError::MissingVolume(container.volume_id))?;
        let relative = Path::new(&container.file_path);
        if relative.is_absolute()
            || relative.components().any(|part| {
                matches!(
                    part,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            return Err(StorageError::InvalidContainer(
                "file_path must remain relative to its configured volume".to_owned(),
            ));
        }
        Ok(volume.mount_path.join(relative))
    }

    fn write_at(
        &self,
        container: &ContainerFile,
        slot_index: u32,
        block: &[u8],
    ) -> Result<(), StorageError> {
        if slot_index >= container.slot_count {
            return Err(StorageError::InvalidContainer(
                "slot index exceeds container slot_count".to_owned(),
            ));
        }
        let path = self.absolute_path(container)?;
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        file.seek(SeekFrom::Start(slot_offset(slot_index)))?;
        file.write_all(block)?;
        file.sync_data()?;
        Ok(())
    }

    fn write_bitmap_header(&self, container_id: u32) -> Result<(), StorageError> {
        let container = self.container(container_id)?;
        let path = self.absolute_path(&container)?;
        write_header(path, &container.occupied_bitmap)
    }

    fn restore_container_files(&self) -> Result<(), StorageError> {
        for container in load_all_containers(&self.connection)? {
            validate_container(&container)?;
            let path = self.absolute_path(&container)?;
            if !path.exists() {
                if occupied_count(&container.occupied_bitmap) > 0 {
                    return Err(StorageError::MissingOccupiedContainer(path));
                }
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(&path)?;
                mark_sparse(&file)?;
                file.set_len(CONTAINER_FILE_BYTES)?;
            } else {
                let file = OpenOptions::new().read(true).write(true).open(&path)?;
                if file.metadata()?.len() != CONTAINER_FILE_BYTES {
                    return Err(StorageError::InvalidContainer(format!(
                        "container file has unexpected logical size: {}",
                        path.display()
                    )));
                }
            }
            write_header(&path, &container.occupied_bitmap)?;
        }
        Ok(())
    }

    fn validate_location_bitmaps(&self) -> Result<(), StorageError> {
        let containers = load_all_containers(&self.connection)?;
        for container in containers {
            let mut actual = vec![0u8; BITMAP_SIZE];
            let mut statement = self
                .connection
                .prepare("SELECT slot_index FROM block_locations WHERE container_id = ?1")?;
            let rows =
                statement.query_map(params![container.container_id], |row| row.get::<_, u32>(0))?;
            for row in rows {
                let slot = row?;
                if slot >= SLOT_COUNT {
                    return Err(StorageError::InvalidContainer(
                        "BlockLocation slot index is out of range".to_owned(),
                    ));
                }
                set_slot(&mut actual, slot, true);
            }
            if actual != container.occupied_bitmap {
                return Err(StorageError::InvalidContainer(format!(
                    "bitmap and BlockLocation rows disagree for container {}",
                    container.container_id
                )));
            }
        }
        Ok(())
    }

    fn validate_identity(owner: &Owner, block_hash: &[u8]) -> Result<(), StorageError> {
        if owner.owner_id.is_empty() || block_hash.is_empty() {
            return Err(StorageError::EmptyIdentity);
        }
        Ok(())
    }

    fn validate_block(block: &[u8]) -> Result<(), StorageError> {
        if block.len() != BLOCK_SIZE {
            return Err(StorageError::InvalidBlockSize(block.len()));
        }
        Ok(())
    }
}

fn persist_container(tx: &Transaction<'_>, container: &ContainerFile) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO containers(container_id, volume_id, owner_type, owner_id,
                               sequence_number, slot_count, occupied_bitmap,
                               file_path, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(container_id) DO UPDATE SET
             volume_id = excluded.volume_id,
             owner_type = excluded.owner_type,
             owner_id = excluded.owner_id,
             sequence_number = excluded.sequence_number,
             slot_count = excluded.slot_count,
             occupied_bitmap = excluded.occupied_bitmap,
             file_path = excluded.file_path,
             created_at = excluded.created_at",
        params![
            container.container_id,
            container.volume_id,
            container.owner_type as u8,
            container.owner_id,
            container.sequence_number,
            container.slot_count,
            container.occupied_bitmap,
            container.file_path,
            container.created_at
        ],
    )?;
    Ok(())
}

fn container_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ContainerFile> {
    let owner_type: u8 = row.get(2)?;
    Ok(ContainerFile {
        container_id: row.get(0)?,
        volume_id: row.get(1)?,
        owner_type: OwnerType::try_from(owner_type).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                2,
                rusqlite::types::Type::Integer,
                Box::new(error),
            )
        })?,
        owner_id: row.get(3)?,
        sequence_number: row.get(4)?,
        slot_count: row.get(5)?,
        occupied_bitmap: row.get(6)?,
        file_path: row.get(7)?,
        created_at: row.get(8)?,
    })
}

fn load_all_containers(connection: &Connection) -> Result<Vec<ContainerFile>, rusqlite::Error> {
    let mut statement = connection.prepare(
        "SELECT container_id, volume_id, owner_type, owner_id, sequence_number,
                slot_count, occupied_bitmap, file_path, created_at
         FROM containers ORDER BY container_id",
    )?;
    let containers = statement
        .query_map([], container_from_row)?
        .collect::<Result<Vec<_>, _>>();
    containers
}

fn load_all_locations(connection: &Connection) -> Result<Vec<BlockLocation>, rusqlite::Error> {
    let mut statement = connection.prepare(
        "SELECT block_hash, container_id, slot_index
         FROM block_locations ORDER BY block_hash",
    )?;
    let locations = statement
        .query_map([], |row| {
            Ok(BlockLocation {
                block_hash: row.get(0)?,
                container_id: row.get(1)?,
                slot_index: row.get(2)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>();
    locations
}

fn validate_container(container: &ContainerFile) -> Result<(), StorageError> {
    if container.slot_count != SLOT_COUNT || container.occupied_bitmap.len() != BITMAP_SIZE {
        return Err(StorageError::InvalidContainer(format!(
            "container {} must have exactly {SLOT_COUNT} slots and {BITMAP_SIZE} bitmap bytes",
            container.container_id
        )));
    }
    Ok(())
}

fn first_free_slot(bitmap: &[u8]) -> Option<u32> {
    bitmap.iter().enumerate().find_map(|(byte_index, byte)| {
        if *byte == u8::MAX {
            return None;
        }
        (0u32..8)
            .find(|bit| *byte & (1u8 << *bit) == 0)
            .map(|bit| (byte_index * 8 + bit as usize) as u32)
    })
}

fn first_available_slot(containers: &[ContainerFile]) -> Option<(u32, u32)> {
    let mut ordered = containers.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|container| container.sequence_number);
    ordered.into_iter().find_map(|container| {
        first_free_slot(&container.occupied_bitmap).map(|slot| (container.container_id, slot))
    })
}

fn set_slot(bitmap: &mut [u8], slot: u32, occupied: bool) {
    let byte = &mut bitmap[(slot / 8) as usize];
    let mask = 1 << (slot % 8);
    if occupied {
        *byte |= mask;
    } else {
        *byte &= !mask;
    }
}

fn slot_is_set(bitmap: &[u8], slot: u32) -> bool {
    bitmap[(slot / 8) as usize] & (1 << (slot % 8)) != 0
}

fn occupied_count(bitmap: &[u8]) -> u32 {
    bitmap.iter().map(|byte| byte.count_ones()).sum()
}

fn slot_offset(slot: u32) -> u64 {
    BITMAP_SIZE as u64 + slot as u64 * BLOCK_SIZE as u64
}

fn write_header(path: impl AsRef<Path>, bitmap: &[u8]) -> Result<(), StorageError> {
    if bitmap.len() != BITMAP_SIZE {
        return Err(StorageError::InvalidContainer(
            "bitmap must be exactly 8192 bytes".to_owned(),
        ));
    }
    let mut file = OpenOptions::new().write(true).open(path)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(bitmap)?;
    file.sync_data()?;
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn path_to_slashes(path: &Path) -> String {
    path.components()
        .map(|part| part.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(unix)]
fn allocated_bytes(metadata: &std::fs::Metadata) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    Some(metadata.blocks().saturating_mul(512))
}

#[cfg(not(unix))]
fn allocated_bytes(_metadata: &std::fs::Metadata) -> Option<u64> {
    None
}

#[cfg(windows)]
fn mark_sparse(file: &File) -> Result<(), StorageError> {
    use std::os::windows::io::AsRawHandle;
    // SAFETY: file handle is valid for the duration of the synchronous call.
    let result = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            0x0009_00c4, // FSCTL_SET_SPARSE
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if result == 0 {
        Err(StorageError::Io(std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn mark_sparse(_file: &File) -> Result<(), StorageError> {
    Ok(())
}

/// Hole-punch where the host OS has a defined implementation; unsupported
/// platforms still clear the logical slot and bitmap and may reuse it.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn punch_hole(path: &Path, offset: u64, length: u64) -> Result<(), StorageError> {
    use std::os::fd::AsRawFd;
    let file = OpenOptions::new().write(true).open(path)?;
    // SAFETY: the descriptor is live and the range is within a validated slot.
    let result = unsafe {
        libc::fallocate(
            file.as_raw_fd(),
            libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
            offset as libc::off_t,
            length as libc::off_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        let error = std::io::Error::last_os_error();
        if matches!(
            error.raw_os_error(),
            Some(libc::EOPNOTSUPP) | Some(libc::ENOSYS) | Some(libc::EINVAL)
        ) {
            Ok(())
        } else {
            Err(StorageError::Io(error))
        }
    }
}

#[cfg(target_os = "macos")]
fn punch_hole(path: &Path, offset: u64, length: u64) -> Result<(), StorageError> {
    use std::os::fd::AsRawFd;
    let file = OpenOptions::new().write(true).open(path)?;
    // The libc binding marks the platform struct non-exhaustive; it contains
    // only integer fields, so a zeroed value is valid before setting inputs.
    let mut range: libc::fpunchhole_t = unsafe { std::mem::zeroed() };
    range.fp_offset = offset as libc::off_t;
    range.fp_length = length as libc::off_t;
    // SAFETY: descriptor and range structure are valid for fcntl(F_PUNCHHOLE).
    let result = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_PUNCHHOLE, &mut range) };
    if result == 0 {
        Ok(())
    } else {
        let error = std::io::Error::last_os_error();
        if matches!(
            error.raw_os_error(),
            Some(libc::EOPNOTSUPP) | Some(libc::ENOSYS) | Some(libc::EINVAL)
        ) {
            Ok(())
        } else {
            Err(StorageError::Io(error))
        }
    }
}

#[cfg(windows)]
fn punch_hole(path: &Path, offset: u64, length: u64) -> Result<(), StorageError> {
    use std::os::windows::io::AsRawHandle;
    let file = OpenOptions::new().write(true).open(path)?;
    #[repr(C)]
    struct FileZeroDataInformation {
        file_offset: i64,
        beyond_final_zero: i64,
    }
    let range = FileZeroDataInformation {
        file_offset: offset as i64,
        beyond_final_zero: (offset + length) as i64,
    };
    let mut returned = 0;
    // SAFETY: file handle and input buffer remain valid for the synchronous call.
    let result = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            0x0009_80c8, // FSCTL_SET_ZERO_DATA
            &range as *const _ as *const _,
            std::mem::size_of::<FileZeroDataInformation>() as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if result != 0 {
        Ok(())
    } else {
        let error = std::io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(1) | Some(50) | Some(87)) {
            Ok(())
        } else {
            Err(StorageError::Io(error))
        }
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    windows
)))]
fn punch_hole(_path: &Path, _offset: u64, _length: u64) -> Result<(), StorageError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static NEXT_ID: AtomicU64 = AtomicU64::new(0);
            loop {
                let path = std::env::temp_dir().join(format!(
                    "p2p-storage-node-test-{}-{}",
                    std::process::id(),
                    NEXT_ID.fetch_add(1, Ordering::Relaxed)
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("failed to create test directory: {error}"),
                }
            }
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn setup(volume_capacities: &[u64]) -> (TempDir, PhysicalStore, Vec<VolumeConfig>) {
        let temp = TempDir::new();
        let volumes = volume_capacities
            .iter()
            .enumerate()
            .map(|(index, capacity)| VolumeConfig {
                volume_id: index as u32,
                mount_path: temp.path().join(format!("vol{index}")),
                max_capacity_bytes: *capacity,
            })
            .collect::<Vec<_>>();
        let store = PhysicalStore::open(temp.path().join("node.sqlite"), volumes.clone()).unwrap();
        (temp, store, volumes)
    }

    fn owner(kind: OwnerType, id: &[u8]) -> Owner {
        Owner::new(kind, id.to_vec()).unwrap()
    }

    fn block(fill: u8) -> Vec<u8> {
        vec![fill; BLOCK_SIZE]
    }

    #[test]
    fn layout_limits_and_bitmap_mapping_are_exact() {
        assert_eq!(BLOCK_SIZE, 65_536);
        assert_eq!(SLOT_COUNT, 65_536);
        assert_eq!(BITMAP_SIZE, 8_192);
        assert_eq!(SLOT_BYTES, 4 * 1024 * 1024 * 1024);
        assert_eq!(CONTAINER_FILE_BYTES, SLOT_BYTES + 8_192);
        assert_eq!(slot_offset(0), 8_192);
        assert_eq!(slot_offset(SLOT_COUNT - 1), 8_192 + 65_535 * 65_536);
        assert_eq!(
            slot_offset(SLOT_COUNT - 1) + BLOCK_SIZE as u64,
            CONTAINER_FILE_BYTES
        );
        let mut bitmap = vec![0; BITMAP_SIZE];
        assert_eq!(first_free_slot(&bitmap), Some(0));
        set_slot(&mut bitmap, SLOT_COUNT - 1, true);
        assert_eq!(bitmap[BITMAP_SIZE - 1], 0x80);
        assert_eq!(occupied_count(&bitmap), 1);
        set_slot(&mut bitmap, SLOT_COUNT - 1, false);
        assert!(bitmap.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn allocator_checks_containers_by_sequence_before_slot_index() {
        let mut earlier = ContainerFile {
            container_id: 12,
            volume_id: 0,
            owner_type: OwnerType::AttachedUser,
            owner_id: b"owner".to_vec(),
            sequence_number: 0,
            slot_count: SLOT_COUNT,
            occupied_bitmap: vec![0xff; BITMAP_SIZE],
            file_path: "ignored".to_owned(),
            created_at: 0,
        };
        set_slot(&mut earlier.occupied_bitmap, 42, false);
        let later = ContainerFile {
            container_id: 13,
            sequence_number: 1,
            occupied_bitmap: vec![0; BITMAP_SIZE],
            ..earlier.clone()
        };
        assert_eq!(
            first_available_slot(&[later, earlier]),
            Some((12, 42)),
            "lowest sequence wins even when a later container has slot zero free"
        );
    }

    #[test]
    fn writes_fixed_sparse_container_and_persists_location() {
        let (_temp, mut store, volumes) = setup(&[SLOT_BYTES]);
        let user = owner(OwnerType::AttachedUser, &[0xab, 0xcd]);
        let hash = [1, 2, 3];
        let expected = block(0x5a);
        let location = store.write_block(&user, &hash, &expected).unwrap();
        assert_eq!(location.container_id, 0);
        assert_eq!(location.slot_index, 0);
        let container = store.container(location.container_id).unwrap();
        assert_eq!(container.slot_count, SLOT_COUNT);
        assert_eq!(container.occupied_bitmap.len(), BITMAP_SIZE);
        assert_eq!(container.occupied_bitmap[0], 1);
        let file = volumes[0].mount_path.join(&container.file_path);
        let metadata = fs::metadata(file).unwrap();
        assert_eq!(metadata.len(), CONTAINER_FILE_BYTES);
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert!(metadata.blocks() * 512 < metadata.len());
        }
        assert_eq!(store.read_block(&hash).unwrap(), Some(expected));

        drop(store);
        let reopened = PhysicalStore::open(_temp.path().join("node.sqlite"), volumes).unwrap();
        assert_eq!(reopened.location(&hash).unwrap(), Some(location));
        assert_eq!(reopened.read_block(&hash).unwrap(), Some(block(0x5a)));
    }

    #[test]
    fn owners_are_isolated_and_paths_use_type_and_hex_id() {
        let (_temp, mut store, volumes) = setup(&[SLOT_BYTES * 3]);
        let user = owner(OwnerType::AttachedUser, &[0x0a, 0xff]);
        let partner = owner(OwnerType::Partner, &[0x0a, 0xff]);
        let user_loc = store.write_block(&user, b"user-hash", &block(1)).unwrap();
        let partner_loc = store
            .write_block(&partner, b"partner-hash", &block(2))
            .unwrap();
        assert_ne!(user_loc.container_id, partner_loc.container_id);
        let user_container = store.container(user_loc.container_id).unwrap();
        let partner_container = store.container(partner_loc.container_id).unwrap();
        assert_eq!(user_container.file_path, "blocks/0/0aff/container-0.bin");
        assert_eq!(partner_container.file_path, "blocks/1/0aff/container-0.bin");
        assert_eq!(store.containers(&user).unwrap().len(), 1);
        assert_eq!(store.containers(&partner).unwrap().len(), 1);
        assert!(volumes[0]
            .mount_path
            .join(user_container.file_path)
            .exists());
    }

    #[test]
    fn reuses_first_slot_and_removes_empty_container() {
        let (temp, mut store, volumes) = setup(&[SLOT_BYTES]);
        let user = owner(OwnerType::AttachedUser, b"user");
        let a = store.write_block(&user, b"a", &block(1)).unwrap();
        let b = store.write_block(&user, b"b", &block(2)).unwrap();
        assert_eq!(a.slot_index, 0);
        assert_eq!(b.slot_index, 1);
        assert!(store.remove_block(b"a").unwrap());
        let reused = store.write_block(&user, b"c", &block(3)).unwrap();
        assert_eq!(reused.container_id, a.container_id);
        assert_eq!(reused.slot_index, a.slot_index);
        assert!(store.remove_block(b"b").unwrap());
        assert!(store.remove_block(b"c").unwrap());
        assert!(store.containers(&user).unwrap().is_empty());
        assert!(!volumes[0]
            .mount_path
            .join("blocks/0/75736572/container-0.bin")
            .exists());
        assert!(!store.remove_block(b"c").unwrap());
        drop(store);
        // Empty state and local cache survive ordinary close/reopen.
        PhysicalStore::open(temp.path().join("node.sqlite"), volumes).unwrap();
    }

    #[test]
    fn padding_replacement_keeps_exact_location_and_slot() {
        let (_temp, mut store, _) = setup(&[SLOT_BYTES]);
        let user = owner(OwnerType::AttachedUser, b"padding-owner");
        let padding_location = store
            .write_block(&user, b"padding-hash", &block(0))
            .unwrap();
        let next_location = store.write_block(&user, b"next-hash", &block(1)).unwrap();
        let replacement = store
            .replace_block(&user, b"padding-hash", b"real-hash", &block(0x7f))
            .unwrap();
        assert_eq!(replacement.container_id, padding_location.container_id);
        assert_eq!(replacement.slot_index, padding_location.slot_index);
        assert_eq!(store.location(b"padding-hash").unwrap(), None);
        assert_eq!(store.location(b"real-hash").unwrap(), Some(replacement));
        assert_eq!(store.location(b"next-hash").unwrap(), Some(next_location));
        assert_eq!(store.read_block(b"real-hash").unwrap(), Some(block(0x7f)));
    }

    #[test]
    fn rewriting_existing_hash_keeps_its_location_and_updates_contents() {
        let (_temp, mut store, _) = setup(&[SLOT_BYTES]);
        let user = owner(OwnerType::AttachedUser, b"rewrite-owner");
        let first = store.write_block(&user, b"same-hash", &block(1)).unwrap();
        let repeated = store.write_block(&user, b"same-hash", &block(2)).unwrap();
        assert_eq!(first, repeated);
        assert_eq!(store.containers(&user).unwrap().len(), 1);
        assert_eq!(
            occupied_count(&store.container(first.container_id).unwrap().occupied_bitmap),
            1
        );
        assert_eq!(store.read_block(b"same-hash").unwrap(), Some(block(2)));
    }

    #[test]
    fn selects_volume_with_greatest_remaining_capacity_for_new_containers() {
        let (_temp, mut store, _) = setup(&[SLOT_BYTES, SLOT_BYTES]);
        let first_owner = owner(OwnerType::AttachedUser, b"first");
        let second_owner = owner(OwnerType::AttachedUser, b"second");
        let first = store.write_block(&first_owner, b"one", &block(1)).unwrap();
        let second = store.write_block(&second_owner, b"two", &block(2)).unwrap();
        assert_eq!(store.container(first.container_id).unwrap().volume_id, 0);
        assert_eq!(store.container(second.container_id).unwrap().volume_id, 1);
    }

    #[test]
    fn validates_input_size_and_location_bitmap_on_restore() {
        let (temp, mut store, volumes) = setup(&[SLOT_BYTES]);
        let user = owner(OwnerType::AttachedUser, b"user");
        assert!(matches!(
            store.write_block(&user, b"bad", &[0; BLOCK_SIZE - 1]),
            Err(StorageError::InvalidBlockSize(_))
        ));
        let location = store.write_block(&user, b"good", &block(9)).unwrap();
        drop(store);
        // Mutate the persisted bitmap to disagree with the local location index.
        let db = Connection::open(temp.path().join("node.sqlite")).unwrap();
        db.execute(
            "UPDATE containers SET occupied_bitmap = ?1 WHERE container_id = ?2",
            params![vec![0u8; BITMAP_SIZE], location.container_id],
        )
        .unwrap();
        drop(db);
        assert!(matches!(
            PhysicalStore::open(temp.path().join("node.sqlite"), volumes),
            Err(StorageError::InvalidContainer(_))
        ));
    }

    #[test]
    fn compaction_snapshots_state_and_owner_purge_cleans_all_volumes() {
        let (temp, mut store, volumes) = setup(&[SLOT_BYTES * 2, SLOT_BYTES]);
        let user = owner(OwnerType::Partner, b"partner");
        let one = store.write_block(&user, b"one", &block(1)).unwrap();
        let two = store.write_block(&user, b"two", &block(2)).unwrap();
        assert!(store.location(b"one").unwrap().is_some());
        store.compact_mutation_log().unwrap();
        let snapshot: Vec<u8> = store
            .connection
            .query_row(
                "SELECT payload FROM mutation_snapshot WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let snapshot: Snapshot = serde_json::from_slice(&snapshot).unwrap();
        assert_eq!(snapshot.locations.len(), 2);
        assert_eq!(
            store
                .connection
                .query_row("SELECT COUNT(*) FROM mutation_log", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(store.remove_owner(&user).unwrap(), 1);
        assert!(store.location(b"one").unwrap().is_none());
        assert!(store.location(b"two").unwrap().is_none());
        assert!(store.containers(&user).unwrap().is_empty());
        assert_eq!(one.container_id, two.container_id);
        drop(store);
        PhysicalStore::open(temp.path().join("node.sqlite"), volumes).unwrap();
    }

    #[test]
    fn allocates_slots_in_container_sequence_order() {
        let (_temp, mut store, volumes) = setup(&[SLOT_BYTES * 2]);
        let user = owner(OwnerType::EmergencyDepositor, b"sequence");
        let first = store.write_block(&user, b"first", &block(1)).unwrap();
        let container = store.container(first.container_id).unwrap();
        // Occupy all slots in the first bitmap to exercise the next-container
        // path without writing 65536 test blocks.
        let mut bitmap = container.occupied_bitmap.clone();
        for slot in 1..SLOT_COUNT {
            set_slot(&mut bitmap, slot, true);
        }
        store
            .connection
            .execute(
                "UPDATE containers SET occupied_bitmap = ?1 WHERE container_id = ?2",
                params![bitmap, first.container_id],
            )
            .unwrap();
        let mut full_container = container;
        full_container.occupied_bitmap = bitmap;
        store
            .containers_cache
            .insert(first.container_id, full_container);
        let second = store.write_block(&user, b"second", &block(2)).unwrap();
        assert_eq!(
            store
                .container(second.container_id)
                .unwrap()
                .sequence_number,
            1
        );
        assert_eq!(second.slot_index, 0);
        assert_eq!(
            volumes[0]
                .mount_path
                .join("blocks/2/73657175656e6365/container-1.bin"),
            volumes[0]
                .mount_path
                .join(store.container(second.container_id).unwrap().file_path)
        );
    }
}
