//! Mesures de référence (cahier de tests RED-06, ADM-04) :
//! `cargo run --release --example perf`. Débits sur la machine courante :
//! chiffrement des blocs, codage de parité, hachage, écriture et relecture
//! du stockage physique.

use std::time::Instant;

use s3m_core::erasure::encode_parity;
use s3m_core::k_block::seal_block;
use s3m_core::symmetric_suite::hash_sha256;
use s3m_node::{Owner, OwnerType, PhysicalStore, VolumeConfig};

const BLOCK: usize = 65_536;
const MIB: f64 = 1024.0 * 1024.0;

fn rate(label: &str, bytes: usize, t: Instant) {
    let s = t.elapsed().as_secs_f64();
    println!("{label:<45} {:>8.1} Mio/s  ({:.2} s pour {} Mio)", bytes as f64 / MIB / s, s, bytes / (1 << 20));
}

fn main() {
    let n = 512; // 32 Mio
    let blocks: Vec<Vec<u8>> = (0..n).map(|i| vec![(i % 251) as u8; BLOCK]).collect();

    let t = Instant::now();
    for b in &blocks {
        std::hint::black_box(seal_block(&[7; 32], &[0, 1], &[3; 12], &b[..BLOCK - 30]).unwrap());
    }
    rate("chiffrement des blocs (ChaCha20-Poly1305)", n * BLOCK, t);

    let t = Instant::now();
    for b in &blocks {
        std::hint::black_box(hash_sha256(b));
    }
    rate("hachage SHA-256", n * BLOCK, t);

    for (k, coef) in [(2usize, 2usize), (4, 3)] {
        let t = Instant::now();
        for chunk in blocks.chunks(k) {
            let refs: Vec<&[u8]> = chunk.iter().map(|b| b.as_slice()).collect();
            if refs.len() == k {
                std::hint::black_box(encode_parity(&refs, coef).unwrap());
            }
        }
        rate(&format!("parité Reed-Solomon k={k}, coef={coef}"), n * BLOCK, t);
    }

    let dir = std::env::temp_dir().join(format!("s3m-perf-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut store = PhysicalStore::open(
        dir.join("perf.sqlite"),
        vec![VolumeConfig { volume_id: 0, mount_path: dir.join("vol"), max_capacity_bytes: 1 << 33 }],
    )
    .unwrap();
    let owner = Owner::new(OwnerType::AttachedUser, vec![1; 32]).unwrap();
    // Blocs distincts (le contenu ci-dessus se répète tous les 251).
    let distinct: Vec<Vec<u8>> = (0..n)
        .map(|i| {
            let mut b = blocks[i].clone();
            b[..8].copy_from_slice(&(i as u64).to_be_bytes());
            b
        })
        .collect();
    let hashes: Vec<[u8; 32]> = distinct.iter().map(|b| hash_sha256(b)).collect();
    let t = Instant::now();
    for (b, h) in distinct.iter().zip(&hashes) {
        store.write_block(&owner, h, b).unwrap();
    }
    rate("écriture du stockage physique (sync)", n * BLOCK, t);
    let t = Instant::now();
    for h in &hashes {
        std::hint::black_box(store.read_block(h).unwrap());
    }
    rate("relecture du stockage physique", n * BLOCK, t);
    drop(store);
    let _ = std::fs::remove_dir_all(&dir);
}
