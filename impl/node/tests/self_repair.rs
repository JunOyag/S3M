//! Invariants de `securite.integrite-autoreparation` (partie node).

use std::collections::HashMap;
use std::path::PathBuf;

use s3m_core::symmetric_suite::hash_sha256;
use s3m_node::self_repair::*;
use s3m_node::{Owner, OwnerType, PhysicalStore, VolumeConfig};

struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn store() -> (Temp, PhysicalStore) {
    let dir = std::env::temp_dir().join(format!("p2p-repair-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let vols = vec![VolumeConfig {
        volume_id: 0,
        mount_path: dir.join("vol0"),
        max_capacity_bytes: 16 * 1024 * 1024,
    }];
    let s = PhysicalStore::open(dir.join("node.sqlite"), vols).unwrap();
    (Temp(dir), s)
}

/// Le Nœud remplace sa copie corrompue par le bloc reconstruit, mais
/// seulement si son hash est correct.
#[test]
fn repair_replaces_corrupted_copy_only_with_a_block_matching_its_hash() {
    let (_t, mut s) = store();
    let owner = Owner::new(OwnerType::AttachedUser, vec![1; 32]).unwrap();
    let good = vec![7u8; 65_536];
    let h = hash_sha256(&good);
    let mut corrupted = good.clone();
    corrupted[10] ^= 1;
    s.write_block(&owner, &h, &corrupted).unwrap();
    assert!(matches!(
        apply_repair(&mut s, &owner, &h, &corrupted),
        Err(RepairError::HashMismatch)
    ));
    apply_repair(&mut s, &owner, &h, &good).unwrap();
    assert_eq!(s.read_block(&h).unwrap().unwrap(), good);
}

/// Scrubbing : détecte blocs corrompus ou absents ; signale un volume à
/// partir de 3 anomalies.
#[test]
fn scrubbing_detects_corruption_and_flags_failing_volumes() {
    let blocks: Vec<Vec<u8>> = (0..6u8).map(|i| vec![i; 100]).collect();
    let mut disk: HashMap<[u8; 32], Vec<u8>> =
        blocks.iter().map(|b| (hash_sha256(b), b.clone())).collect();
    let hashes: Vec<[u8; 32]> = blocks.iter().map(|b| hash_sha256(b)).collect();
    // Volume 1 : 3 anomalies (2 corrompus, 1 absent) ; volume 0 : 1 anomalie.
    disk.get_mut(&hashes[0]).unwrap()[0] ^= 1;
    disk.get_mut(&hashes[3]).unwrap()[0] ^= 1;
    disk.get_mut(&hashes[4]).unwrap()[0] ^= 1;
    disk.remove(&hashes[5]);
    let layout: Vec<([u8; 32], u32)> = hashes
        .iter()
        .enumerate()
        .map(|(i, h)| (*h, if i < 3 { 0 } else { 1 }))
        .collect();
    let r = scrub(&layout, &|h| disk.get(h).cloned());
    assert_eq!(r.checked, 6);
    assert_eq!(
        r.corrupted,
        vec![hashes[0], hashes[3], hashes[4], hashes[5]]
    );
    assert_eq!(r.failing_volumes, vec![1]);
}
