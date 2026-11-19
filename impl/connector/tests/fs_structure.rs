//! Invariants de `protocols.fs-structure` (component connector).

use std::collections::HashMap;

use p2p_storage_connector::fs::*;
use p2p_storage_protocol::layout::FILE_BLOCK_DATA_BYTES;

const MK: [u8; 32] = [0x10; 32];

fn store(chain: &Chain) -> HashMap<BlockHash, Vec<u8>> {
    chain.blocks.iter().cloned().collect()
}

fn write(data: &[u8], salt: [u8; 16]) -> Chain {
    let mut n = 0u8;
    let mut nonce = || {
        n = n.wrapping_add(1);
        [n; 12]
    };
    write_file(
        data,
        &mut Sealing {
            master_key: &MK,
            encryption_salt: &salt,
            nonce: &mut nonce,
        },
    )
    .unwrap()
}

/// Fichier sur plusieurs blocs : aller-retour exact, `size_bytes` retire le
/// padding, chaînage `next_hash` = hash du bloc chiffré suivant.
#[test]
fn multi_block_file_roundtrips_and_chains_by_ciphertext_hash() {
    let data: Vec<u8> = (0..2 * FILE_BLOCK_DATA_BYTES + 10)
        .map(|i| i as u8)
        .collect();
    let chain = write(&data, [1; 16]);
    assert_eq!(chain.blocks.len(), 3);
    assert!(chain.blocks.iter().all(|(_, f)| f.len() == 65_536));
    let s = store(&chain);
    let back = read_file(&chain.first, data.len() as u64, &MK, &[1; 16], &|h| {
        s.get(h).cloned()
    })
    .unwrap();
    assert_eq!(back, data);
    for (h, f) in &chain.blocks {
        assert_eq!(*h, p2p_storage_core::symmetric_suite::hash_sha256(f));
    }
}

#[test]
fn empty_file_is_one_block() {
    let chain = write(&[], [2; 16]);
    assert_eq!(chain.blocks.len(), 1);
    let s = store(&chain);
    assert_eq!(
        read_file(&chain.first, 0, &MK, &[2; 16], &|h| s.get(h).cloned()).unwrap(),
        Vec::<u8>::new()
    );
}

/// Réémission avec un sel neuf : tous les blocs changent (nouvelle chaîne,
/// nouveau `first_block_hash`) ; l'ancienne reste lisible jusqu'à sa purge.
#[test]
fn reemission_with_fresh_salt_produces_an_entirely_new_chain() {
    let data = vec![7u8; 100_000];
    let a = write(&data, [3; 16]);
    let b = write(&data, [4; 16]);
    assert_ne!(a.first, b.first);
    assert!(a
        .blocks
        .iter()
        .all(|(h, _)| b.blocks.iter().all(|(h2, _)| h != h2)));
    let s = store(&a);
    assert_eq!(
        read_file(&a.first, data.len() as u64, &MK, &[3; 16], &|h| s
            .get(h)
            .cloned())
        .unwrap(),
        data
    );
}

/// Intégrité : un bloc altéré, absent, ou déchiffré avec le mauvais sel est rejeté.
#[test]
fn tampered_or_missing_blocks_are_rejected() {
    let data = vec![9u8; 70_000];
    let chain = write(&data, [5; 16]);
    let mut s = store(&chain);
    let second = chain.blocks[1].0;
    s.get_mut(&second).unwrap()[500] ^= 1;
    assert!(matches!(
        read_file(&chain.first, data.len() as u64, &MK, &[5; 16], &|h| s
            .get(h)
            .cloned()),
        Err(FsError::HashMismatch)
    ));
    let s = store(&chain);
    assert!(matches!(
        read_file(&chain.first, data.len() as u64, &MK, &[6; 16], &|h| s
            .get(h)
            .cloned()),
        Err(FsError::Core(_))
    ));
    assert!(matches!(
        read_file(&chain.first, data.len() as u64, &MK, &[5; 16], &|_| None),
        Err(FsError::MissingBlock)
    ));
}

fn entry(i: usize) -> Entry {
    Entry {
        name: format!("fichier-{i:05}-nom-de-trente-deux"),
        size_bytes: i as u64,
        mime_type: "application/octet-stream".into(),
        first_block_hash: [i as u8; 32],
        encryption_salt: [i as u8; 16],
        key_version: 1,
        permissions: 0o644,
        created_at: 1,
        modified_at: 2,
    }
}

/// Répertoire de 400 entrées : chaîné sur plusieurs `DirectoryBlock`,
/// aller-retour exact ; répertoire vide = un bloc.
#[test]
fn large_directory_spans_chained_blocks_and_roundtrips() {
    let entries: Vec<Entry> = (0..400).map(entry).collect();
    let mut n = 0u8;
    let mut nonce = || {
        n = n.wrapping_add(1);
        [n; 12]
    };
    let mut sealing = Sealing {
        master_key: &MK,
        encryption_salt: &[8; 16],
        nonce: &mut nonce,
    };
    let chain = write_directory(&entries, &mut sealing).unwrap();
    assert!(chain.blocks.len() >= 2);
    let s = store(&chain);
    assert_eq!(
        read_directory(&chain.first, &MK, &[8; 16], &|h| s.get(h).cloned()).unwrap(),
        entries
    );

    let empty = write_directory(&[], &mut sealing).unwrap();
    assert_eq!(empty.blocks.len(), 1);
    let s = store(&empty);
    assert!(
        read_directory(&empty.first, &MK, &[8; 16], &|h| s.get(h).cloned())
            .unwrap()
            .is_empty()
    );
}
