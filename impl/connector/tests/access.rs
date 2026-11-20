//! `protocols.acces-applicatif` : résolution de chemins, lecture paresseuse,
//! chemin de secours.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use s3m_connector::access::*;
use s3m_connector::fs::{write_directory, write_file, BlockHash, Entry, Sealing};
use s3m_connector::integrity::BlockSource;

const MK: [u8; 32] = [0x10; 32];

/// Stockage en mémoire : le Nœud peut « perdre » des blocs ; la
/// reconstruction (partenaires) les rend toujours. Compte les accès.
#[derive(Default)]
struct Store {
    blocks: HashMap<BlockHash, Vec<u8>>,
    node_lost: HashSet<BlockHash>,
    fetched: RefCell<Vec<BlockHash>>,
    reconstructed: RefCell<usize>,
}

impl BlockSource for Store {
    fn fetch_from_node(&self, h: &BlockHash) -> Option<Vec<u8>> {
        self.fetched.borrow_mut().push(*h);
        if self.node_lost.contains(h) {
            return None;
        }
        self.blocks.get(h).cloned()
    }
    fn reconstruct(&self, h: &BlockHash) -> Option<Vec<u8>> {
        *self.reconstructed.borrow_mut() += 1;
        self.blocks.get(h).cloned()
    }
}

fn entry(name: &str, mime: &str, first: BlockHash, salt: [u8; 16], size: u64) -> Entry {
    Entry {
        name: name.into(),
        size_bytes: size,
        mime_type: mime.into(),
        first_block_hash: first,
        encryption_salt: salt,
        key_version: 1,
        permissions: 0o644,
        created_at: 1,
        modified_at: 1,
    }
}

/// `/` → { docs/ → { a.txt, b.bin }, c.txt }
fn tree(store: &mut Store) -> (Root, BlockHash, BlockHash) {
    let mut n = 0u8;
    let mut nonce = || {
        n = n.wrapping_add(1);
        [n; 12]
    };
    let put =
        |data: &[u8], salt: [u8; 16], store: &mut Store, nonce: &mut dyn FnMut() -> [u8; 12]| {
            let c = write_file(
                data,
                &mut Sealing {
                    master_key: &MK,
                    encryption_salt: &salt,
                    nonce,
                },
            )
            .unwrap();
            store.blocks.extend(c.blocks.iter().cloned());
            c.first
        };
    let a = put(b"contenu de a", [1; 16], store, &mut nonce);
    let b = put(&vec![7u8; 200_000], [2; 16], store, &mut nonce);
    let c = put(b"contenu de c", [3; 16], store, &mut nonce);
    let docs = write_directory(
        &[
            entry("a.txt", "text/plain", a, [1; 16], 12),
            entry("b.bin", "application/octet-stream", b, [2; 16], 200_000),
        ],
        &mut Sealing {
            master_key: &MK,
            encryption_salt: &[4; 16],
            nonce: &mut nonce,
        },
    )
    .unwrap();
    store.blocks.extend(docs.blocks.iter().cloned());
    let root = write_directory(
        &[
            entry("docs", DIRECTORY_MIME, docs.first, [4; 16], 0),
            entry("c.txt", "text/plain", c, [3; 16], 12),
        ],
        &mut Sealing {
            master_key: &MK,
            encryption_salt: &[5; 16],
            nonce: &mut nonce,
        },
    )
    .unwrap();
    store.blocks.extend(root.blocks.iter().cloned());
    (
        Root {
            fs_root_hash: root.first,
            encryption_salt: [5; 16],
            key_version: 1,
        },
        a,
        b,
    )
}

fn keys() -> HashMap<u16, [u8; 32]> {
    [(1, MK)].into()
}

#[test]
fn paths_resolve_through_directories() {
    let mut s = Store::default();
    let (root, _, _) = tree(&mut s);
    let k = keys();
    let v = Volume::new(&s, &k, root);
    let names: Vec<String> = v.list("/").unwrap().into_iter().map(|e| e.name).collect();
    assert_eq!(names, vec!["docs", "c.txt"]);
    assert_eq!(v.list("/docs").unwrap().len(), 2);
    assert_eq!(v.read("/docs/a.txt").unwrap(), b"contenu de a");
    assert!(matches!(v.read("/docs/zz"), Err(AccessError::NotFound(_))));
    assert!(matches!(
        v.list("/c.txt"),
        Err(AccessError::NotADirectory(_))
    ));
}

/// Récupération paresseuse : lire `/docs/a.txt` ne touche aucun bloc de
/// `b.bin` (4 blocs) ni de `c.txt`.
#[test]
fn reading_one_file_fetches_only_the_blocks_on_its_path() {
    let mut s = Store::default();
    let (root, a, b) = tree(&mut s);
    let k = keys();
    let v = Volume::new(&s, &k, root.clone());
    v.read("/docs/a.txt").unwrap();
    let fetched = s.fetched.borrow();
    assert_eq!(fetched.len(), 3, "racine, docs, a.txt");
    assert!(fetched.contains(&root.fs_root_hash));
    assert!(fetched.contains(&a));
    assert!(!fetched.contains(&b));
}

/// Nœud injoignable pour un bloc : chemin de secours (reconstruction),
/// incident journalisé.
#[test]
fn missing_node_block_is_served_by_the_rescue_path() {
    let mut s = Store::default();
    let (root, a, _) = tree(&mut s);
    s.node_lost.insert(a);
    let k = keys();
    let v = Volume::new(&s, &k, root);
    assert_eq!(v.read("/docs/a.txt").unwrap(), b"contenu de a");
    assert_eq!(*s.reconstructed.borrow(), 1);
    assert_eq!(v.integrity.borrow().pending_incidents.len(), 1);
}
