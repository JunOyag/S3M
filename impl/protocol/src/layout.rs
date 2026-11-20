//! Capacités de bloc mesurées sur les types FlatBuffers générés — ids
//! `fs.FileBlock` et `fs.DirectoryBlock` (Phase 1). Réf. spec :
//! docs/04-protocols/fs-structure.md, docs/03-crypto/k-block.md (format de
//! bloc : 65 506 o de clair par bloc).

use flatbuffers::FlatBufferBuilder;
use s3m_core::k_block::BLOCK_PLAINTEXT_LEN;

use crate::fb::fs::{
    Attributes, AttributesArgs, DirectoryBlock, DirectoryBlockArgs, DirectoryEntry,
    DirectoryEntryArgs, FileBlock, FileBlockArgs,
};

/// Taille d'un hash SHA-256 (`next_hash`, `first_block_hash`).
pub const HASH_LEN: usize = 32;

/// Plus grande taille de `data` pour laquelle un `FileBlock` sérialisé,
/// **avec** un `next_hash` de 32 o, tient dans [`BLOCK_PLAINTEXT_LEN`].
/// Valeur mesurée par `tests/layout.rs` (`file_block_data_bytes_is_measured`).
pub const FILE_BLOCK_DATA_BYTES: usize = 65_440;

/// Nombre d'entrées d'un `DirectoryBlock` de référence (voir
/// [`reference_directory_entry`]) tenant dans un bloc, avec `next_hash`.
/// Mesuré par `tests/layout.rs` ; la capacité réelle dépend de la longueur
/// des noms et des métadonnées — le Connecteur mesure chaque bloc avant
/// émission.
pub const DIRECTORY_BLOCK_REFERENCE_ENTRIES: usize = 333;

/// Longueur sérialisée d'un `FileBlock` portant `data_len` octets et un
/// `next_hash` (ou aucun si `with_next_hash` est faux).
pub fn serialized_file_block_len(data_len: usize, with_next_hash: bool) -> usize {
    let mut fbb = FlatBufferBuilder::with_capacity(data_len + 256);
    let data = fbb.create_vector(&vec![0u8; data_len]);
    let next_hash = with_next_hash.then(|| fbb.create_vector(&[0u8; HASH_LEN]));
    let root = FileBlock::create(
        &mut fbb,
        &FileBlockArgs {
            data: Some(data),
            next_hash,
        },
    );
    fbb.finish_minimal(root);
    fbb.finished_data().len()
}

/// Entrée de référence pour la mesure de capacité d'un `DirectoryBlock` :
/// nom de 32 o, type MIME de 24 o, hash de 32 o, sel de 16 o, sans
/// métadonnée libre.
pub fn reference_directory_entry<'a>(
    fbb: &mut FlatBufferBuilder<'a>,
) -> flatbuffers::WIPOffset<DirectoryEntry<'a>> {
    let name = fbb.create_string(&"n".repeat(32));
    let mime = fbb.create_string(&"m".repeat(24));
    let hash = fbb.create_vector(&[0u8; HASH_LEN]);
    let salt = fbb.create_vector(&[0u8; 16]);
    let attributes = Attributes::create(
        fbb,
        &AttributesArgs {
            permissions: 0o644,
            created_at: u64::MAX,
            modified_at: u64::MAX,
        },
    );
    DirectoryEntry::create(
        fbb,
        &DirectoryEntryArgs {
            name: Some(name),
            size_bytes: u64::MAX,
            mime_type: Some(mime),
            first_block_hash: Some(hash),
            attributes: Some(attributes),
            encryption_salt: Some(salt),
            key_version: u16::MAX,
            metadata: None,
        },
    )
}

/// Longueur sérialisée d'un `DirectoryBlock` de `entries` entrées de
/// référence, avec `next_hash`.
pub fn serialized_reference_directory_block_len(entries: usize) -> usize {
    let mut fbb = FlatBufferBuilder::with_capacity(BLOCK_PLAINTEXT_LEN);
    let items: Vec<_> = (0..entries)
        .map(|_| reference_directory_entry(&mut fbb))
        .collect();
    let entries = fbb.create_vector(&items);
    let next_hash = fbb.create_vector(&[0u8; HASH_LEN]);
    let root = DirectoryBlock::create(
        &mut fbb,
        &DirectoryBlockArgs {
            entries: Some(entries),
            next_hash: Some(next_hash),
        },
    );
    fbb.finish_minimal(root);
    fbb.finished_data().len()
}

/// Vrai si un buffer sérialisé tient dans le clair d'un bloc.
pub fn fits_in_block(serialized_len: usize) -> bool {
    serialized_len <= BLOCK_PLAINTEXT_LEN
}
