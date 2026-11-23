//! Structure du système de fichiers — id `protocols.fs-structure`, component
//! `connector` (Phase 3). Réf. spec : docs/04-protocols/fs-structure.md.
//!
//! - Un fichier est une chaîne de `FileBlock` (≤ `FILE_BLOCK_DATA_BYTES` de
//!   données chacun), un répertoire une chaîne de `DirectoryBlock`, chaînées
//!   par `next_hash` = hash SHA-256 du bloc **chiffré** suivant.
//! - Chiffrement du **dernier bloc vers le premier** sous
//!   `K_block = KDF(master_key, "block", encryption_salt, u32(index))`.
//! - Une modification réémet toute la chaîne avec un `encryption_salt` neuf.
//! - Lecture : chaque bloc reçu est vérifié contre le hash attendu avant
//!   déchiffrement ; `size_bytes` fait foi pour retirer le padding.

use flatbuffers::FlatBufferBuilder;
use s3m_core::k_block::{
    derive_k_block, derive_k_block_from_elem, derive_k_elem, open_block, seal_block,
    unwrap_child_key, wrap_child_key, BLOCK_PLAINTEXT_LEN, WRAPPED_KEY_LEN,
};
use s3m_core::symmetric_suite::hash_sha256;
use s3m_core::CoreError;
use s3m_protocol::fb::fs;
use s3m_protocol::layout::FILE_BLOCK_DATA_BYTES;

/// En-tête de version des blocs (version de protocole 1).
pub const BLOCK_HEADER: [u8; 2] = s3m_core::version::CURRENT_HEADER;

/// Hash d'un bloc chiffré.
pub type BlockHash = [u8; 32];

/// Erreurs FS.
#[derive(Debug, thiserror::Error)]
pub enum FsError {
    #[error(transparent)]
    Core(#[from] CoreError),
    #[error("bloc introuvable")]
    MissingBlock,
    #[error("hash du bloc reçu différent du hash attendu")]
    HashMismatch,
    #[error("bloc mal formé : {0}")]
    Format(&'static str),
    #[error("entrée de répertoire trop grande pour un bloc")]
    EntryTooLarge,
}

/// Chaîne de blocs chiffrés prête à l'envoi (`write_block` dans l'ordre).
#[derive(Debug, Clone)]
pub struct Chain {
    /// Hash du premier bloc (`first_block_hash` / `fs_root_hash`).
    pub first: BlockHash,
    /// `(hash, trame de 65 536 o)`, du premier au dernier bloc.
    pub blocks: Vec<(BlockHash, Vec<u8>)>,
}

/// Paramètres de chiffrement d'une version d'élément.
pub struct Sealing<'a> {
    pub master_key: &'a [u8; 32],
    /// 16 o CSPRNG, neuf à chaque création ou réémission.
    pub encryption_salt: &'a [u8; 16],
    /// Source de nonces aléatoires (12 o).
    pub nonce: &'a mut dyn FnMut() -> [u8; 12],
}

/// Chiffre une suite de clairs (chacun ≤ 65 506 o, sans `next_hash`) en
/// chaîne : `build(i, next_hash)` sérialise le bloc `i`. Ordre de
/// chiffrement : du dernier au premier.
fn seal_chain(
    count: usize,
    sealing: &mut Sealing<'_>,
    build: &dyn Fn(usize, Option<&BlockHash>) -> Vec<u8>,
) -> Result<Chain, FsError> {
    let mut blocks = Vec::with_capacity(count);
    let mut next: Option<BlockHash> = None;
    for i in (0..count).rev() {
        let clear = build(i, next.as_ref());
        let k = derive_k_block(sealing.master_key, sealing.encryption_salt, i as u32)?;
        let frame = seal_block(&k, &BLOCK_HEADER, &(sealing.nonce)(), &clear)?;
        let hash = hash_sha256(&frame);
        blocks.push((hash, frame));
        next = Some(hash);
    }
    blocks.reverse();
    Ok(Chain {
        first: blocks[0].0,
        blocks,
    })
}

/// Extrait le `next_hash` d'un bloc déchiffré.
type NextOf<'a> = dyn Fn(&[u8]) -> Result<Option<BlockHash>, FsError> + 'a;

/// Hashes de la chaîne d'un fichier ou d'un répertoire (déchiffrée pour
/// suivre `next_hash`).
pub fn chain_hashes(
    first: &BlockHash,
    k_elem: &[u8; 32],
    is_dir: bool,
    get: &dyn Fn(&BlockHash) -> Option<Vec<u8>>,
) -> Result<Vec<BlockHash>, FsError> {
    let parse = |clear: &[u8]| -> Result<Option<BlockHash>, FsError> {
        if is_dir {
            let b = flatbuffers::root::<fs::DirectoryBlock>(clear)
                .map_err(|_| FsError::Format("DirectoryBlock"))?;
            next_hash_of(b.next_hash())
        } else {
            let b = flatbuffers::root::<fs::FileBlock>(clear)
                .map_err(|_| FsError::Format("FileBlock"))?;
            next_hash_of(b.next_hash())
        }
    };
    let mut out = Vec::new();
    let mut cursor = Some(*first);
    while let Some(h) = cursor {
        let frame = get(&h).ok_or(FsError::MissingBlock)?;
        let k = derive_k_block_from_elem(k_elem, out.len() as u32)?;
        let clear = open_block(&k, &BLOCK_HEADER, &frame)?;
        cursor = parse(&clear)?;
        out.push(h);
    }
    Ok(out)
}

/// Lit et déchiffre la chaîne qui commence à `first` ; `next(clear)` rend le
/// `next_hash` du bloc déchiffré.
fn open_chain(
    first: &BlockHash,
    k_elem: &[u8; 32],
    get: &dyn Fn(&BlockHash) -> Option<Vec<u8>>,
    next_of: &NextOf<'_>,
) -> Result<Vec<Vec<u8>>, FsError> {
    let mut out = Vec::new();
    let mut cursor = Some(*first);
    while let Some(h) = cursor {
        let frame = get(&h).ok_or(FsError::MissingBlock)?;
        if hash_sha256(&frame) != h {
            return Err(FsError::HashMismatch);
        }
        let k = derive_k_block_from_elem(k_elem, out.len() as u32)?;
        let clear = open_block(&k, &BLOCK_HEADER, &frame)?;
        cursor = next_of(&clear)?;
        out.push(clear);
    }
    Ok(out)
}

fn file_block_bytes(data: &[u8], next: Option<&BlockHash>) -> Vec<u8> {
    let mut fbb = FlatBufferBuilder::with_capacity(BLOCK_PLAINTEXT_LEN);
    let d = fbb.create_vector(data);
    let n = next.map(|h| fbb.create_vector(h));
    let b = fs::FileBlock::create(
        &mut fbb,
        &fs::FileBlockArgs {
            data: Some(d),
            next_hash: n,
        },
    );
    fbb.finish_minimal(b);
    fbb.finished_data().to_vec()
}

/// Encode un fichier en chaîne de `FileBlock` chiffrés.
pub fn write_file(data: &[u8], sealing: &mut Sealing<'_>) -> Result<Chain, FsError> {
    let chunks: Vec<&[u8]> = if data.is_empty() {
        vec![&[][..]]
    } else {
        data.chunks(FILE_BLOCK_DATA_BYTES).collect()
    };
    seal_chain(chunks.len(), sealing, &|i, next| {
        file_block_bytes(chunks[i], next)
    })
}

fn next_hash_of(v: Option<flatbuffers::Vector<'_, u8>>) -> Result<Option<BlockHash>, FsError> {
    match v {
        None => Ok(None),
        Some(h) if h.is_empty() => Ok(None),
        Some(h) => h
            .bytes()
            .try_into()
            .map(Some)
            .map_err(|_| FsError::Format("next_hash")),
    }
}

/// Lit un fichier ; `size_bytes` retire le padding du dernier bloc.
pub fn read_file(
    first: &BlockHash,
    size_bytes: u64,
    master_key: &[u8; 32],
    salt: &[u8; 16],
    get: &dyn Fn(&BlockHash) -> Option<Vec<u8>>,
) -> Result<Vec<u8>, FsError> {
    read_file_elem(first, size_bytes, &derive_k_elem(master_key, salt)?, get)
}

/// Lit un fichier avec sa seule clé d'élément (destinataire d'un partage,
/// `protocols.partage`).
pub fn read_file_elem(
    first: &BlockHash,
    size_bytes: u64,
    k_elem: &[u8; 32],
    get: &dyn Fn(&BlockHash) -> Option<Vec<u8>>,
) -> Result<Vec<u8>, FsError> {
    let parse = |clear: &[u8]| -> Result<Option<BlockHash>, FsError> {
        let b =
            flatbuffers::root::<fs::FileBlock>(clear).map_err(|_| FsError::Format("FileBlock"))?;
        next_hash_of(b.next_hash())
    };
    let blocks = open_chain(first, k_elem, get, &parse)?;
    let mut out = Vec::new();
    for clear in &blocks {
        let b =
            flatbuffers::root::<fs::FileBlock>(clear).map_err(|_| FsError::Format("FileBlock"))?;
        out.extend_from_slice(b.data().map(|d| d.bytes()).unwrap_or_default());
    }
    if (out.len() as u64) < size_bytes {
        return Err(FsError::Format("size_bytes supérieur au contenu"));
    }
    out.truncate(size_bytes as usize);
    Ok(out)
}

/// Entrée de répertoire (fichier ou sous-répertoire). L'égalité ignore
/// `wrapped_key`, donnée dérivée recalculée à chaque écriture.
#[derive(Debug, Clone, Default)]
pub struct Entry {
    pub name: String,
    pub size_bytes: u64,
    pub mime_type: String,
    pub first_block_hash: BlockHash,
    pub encryption_salt: [u8; 16],
    pub key_version: u16,
    pub permissions: u16,
    pub created_at: u64,
    pub modified_at: u64,
    /// Clé d'élément de l'entrée chiffrée sous celle du répertoire
    /// (`protocols.partage`) : lue telle quelle, recalculée à l'écriture.
    pub wrapped_key: Vec<u8>,
}

impl PartialEq for Entry {
    fn eq(&self, o: &Self) -> bool {
        self.name == o.name
            && self.size_bytes == o.size_bytes
            && self.mime_type == o.mime_type
            && self.first_block_hash == o.first_block_hash
            && self.encryption_salt == o.encryption_salt
            && self.key_version == o.key_version
            && self.permissions == o.permissions
            && self.created_at == o.created_at
            && self.modified_at == o.modified_at
    }
}

impl Eq for Entry {}

fn directory_block_bytes(entries: &[Entry], next: Option<&BlockHash>) -> Vec<u8> {
    let mut fbb = FlatBufferBuilder::with_capacity(BLOCK_PLAINTEXT_LEN);
    let items: Vec<_> = entries
        .iter()
        .map(|e| {
            let name = fbb.create_string(&e.name);
            let mime = fbb.create_string(&e.mime_type);
            let h = fbb.create_vector(&e.first_block_hash);
            let s = fbb.create_vector(&e.encryption_salt);
            let w = (!e.wrapped_key.is_empty()).then(|| fbb.create_vector(&e.wrapped_key));
            let a = fs::Attributes::create(
                &mut fbb,
                &fs::AttributesArgs {
                    permissions: e.permissions,
                    created_at: e.created_at,
                    modified_at: e.modified_at,
                },
            );
            fs::DirectoryEntry::create(
                &mut fbb,
                &fs::DirectoryEntryArgs {
                    name: Some(name),
                    size_bytes: e.size_bytes,
                    mime_type: Some(mime),
                    first_block_hash: Some(h),
                    attributes: Some(a),
                    encryption_salt: Some(s),
                    key_version: e.key_version,
                    metadata: None,
                    wrapped_key: w,
                },
            )
        })
        .collect();
    let v = fbb.create_vector(&items);
    let n = next.map(|h| fbb.create_vector(h));
    let b = fs::DirectoryBlock::create(
        &mut fbb,
        &fs::DirectoryBlockArgs {
            entries: Some(v),
            next_hash: n,
        },
    );
    fbb.finish_minimal(b);
    fbb.finished_data().to_vec()
}

/// Répartit les entrées en blocs : chaque bloc est rempli tant que sa
/// sérialisation (avec un `next_hash` de 32 o) tient dans 65 506 o.
pub fn pack_directory(entries: &[Entry]) -> Result<Vec<std::ops::Range<usize>>, FsError> {
    let probe = [0u8; 32];
    // Taille comptée avec une clé d'enfant chiffrée par entrée.
    let sized: Vec<Entry> = entries
        .iter()
        .map(|e| Entry {
            wrapped_key: vec![0; WRAPPED_KEY_LEN],
            ..e.clone()
        })
        .collect();
    let entries = &sized[..];
    let mut ranges = Vec::new();
    let mut start = 0;
    while start < entries.len() || ranges.is_empty() {
        let mut end = start;
        while end < entries.len()
            && directory_block_bytes(&entries[start..=end], Some(&probe)).len()
                <= BLOCK_PLAINTEXT_LEN
        {
            end += 1;
        }
        if end == start && start < entries.len() {
            return Err(FsError::EntryTooLarge);
        }
        ranges.push(start..end);
        start = end;
        if entries.is_empty() {
            break;
        }
    }
    Ok(ranges)
}

/// Encode un répertoire en chaîne de `DirectoryBlock` chiffrés.
pub fn write_directory(entries: &[Entry], sealing: &mut Sealing<'_>) -> Result<Chain, FsError> {
    // Clé de chaque enfant chiffrée sous celle de ce répertoire.
    let parent = derive_k_elem(sealing.master_key, sealing.encryption_salt)?;
    let mut keyed = entries.to_vec();
    for e in &mut keyed {
        let child = derive_k_elem(sealing.master_key, &e.encryption_salt)?;
        e.wrapped_key = wrap_child_key(&parent, &child, &e.encryption_salt, &(sealing.nonce)())?;
    }
    let entries = &keyed[..];
    let ranges = pack_directory(entries)?;
    seal_chain(ranges.len(), sealing, &|i, next| {
        directory_block_bytes(&entries[ranges[i].clone()], next)
    })
}

/// Lit un répertoire (toutes les entrées de la chaîne).
pub fn read_directory(
    first: &BlockHash,
    master_key: &[u8; 32],
    salt: &[u8; 16],
    get: &dyn Fn(&BlockHash) -> Option<Vec<u8>>,
) -> Result<Vec<Entry>, FsError> {
    read_directory_elem(first, &derive_k_elem(master_key, salt)?, get)
}

/// Clé d'élément d'une entrée lue avec la clé de son répertoire
/// (destinataire d'un partage).
pub fn child_key(dir_k_elem: &[u8; 32], e: &Entry) -> Result<[u8; 32], FsError> {
    Ok(unwrap_child_key(
        dir_k_elem,
        &e.wrapped_key,
        &e.encryption_salt,
    )?)
}

/// Lit un répertoire avec sa seule clé d'élément.
pub fn read_directory_elem(
    first: &BlockHash,
    k_elem: &[u8; 32],
    get: &dyn Fn(&BlockHash) -> Option<Vec<u8>>,
) -> Result<Vec<Entry>, FsError> {
    let parse = |clear: &[u8]| -> Result<Option<BlockHash>, FsError> {
        let b = flatbuffers::root::<fs::DirectoryBlock>(clear)
            .map_err(|_| FsError::Format("DirectoryBlock"))?;
        next_hash_of(b.next_hash())
    };
    let blocks = open_chain(first, k_elem, get, &parse)?;
    let mut out = Vec::new();
    for clear in &blocks {
        let b = flatbuffers::root::<fs::DirectoryBlock>(clear)
            .map_err(|_| FsError::Format("DirectoryBlock"))?;
        for e in b.entries().iter().flatten() {
            let attrs = e.attributes();
            out.push(Entry {
                name: e.name().unwrap_or_default().to_owned(),
                size_bytes: e.size_bytes(),
                mime_type: e.mime_type().unwrap_or_default().to_owned(),
                first_block_hash: e
                    .first_block_hash()
                    .and_then(|h| h.bytes().try_into().ok())
                    .ok_or(FsError::Format("first_block_hash"))?,
                encryption_salt: e
                    .encryption_salt()
                    .and_then(|h| h.bytes().try_into().ok())
                    .ok_or(FsError::Format("encryption_salt"))?,
                key_version: e.key_version(),
                permissions: attrs.map_or(0, |a| a.permissions()),
                created_at: attrs.map_or(0, |a| a.created_at()),
                modified_at: attrs.map_or(0, |a| a.modified_at()),
                wrapped_key: e
                    .wrapped_key()
                    .map(|w| w.bytes().to_vec())
                    .unwrap_or_default(),
            });
        }
    }
    Ok(out)
}
