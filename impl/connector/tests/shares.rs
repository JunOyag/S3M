//! Partages côté Connecteur (`protocols.partage#connecteur`) : élément à
//! confier, dossier « Partagés avec moi » en lecture seule, publication due.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use s3m_connector::drive::*;
use s3m_connector::fs::BlockHash;
use s3m_connector::shares::*;

#[derive(Default)]
struct MemNode {
    blocks: Mutex<HashMap<BlockHash, Vec<u8>>>,
    root: Mutex<BlockHash>,
}

impl BlockIo for MemNode {
    fn get(&self, h: &BlockHash) -> Option<Vec<u8>> {
        self.blocks.lock().unwrap().get(h).cloned()
    }
    fn put(&self, h: &BlockHash, frame: Vec<u8>) -> Result<(), String> {
        self.blocks.lock().unwrap().insert(*h, frame);
        Ok(())
    }
    fn commit(&self, base: &BlockHash, new: &BlockHash) -> Result<Option<BlockHash>, String> {
        let mut r = self.root.lock().unwrap();
        if *r != *base {
            return Ok(Some(*r));
        }
        *r = *new;
        Ok(None)
    }
}

fn workspace(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("p2p-shares-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

#[test]
fn shared_folder_is_readable_by_the_recipient_and_read_only() {
    // Propriétaire : un dossier synchronisé chez son Nœud.
    let owner_node = Arc::new(MemNode::default());
    let mut owner = Drive::open(
        owner_node.clone(),
        [9; 32],
        workspace("owner"),
        Arc::new(|| 1000),
    )
    .unwrap();
    owner.create("/Photos", true).unwrap();
    owner.create("/Photos/vacances.txt", false).unwrap();
    owner
        .write("/Photos/vacances.txt", 0, b"plage et soleil")
        .unwrap();
    owner.create("/Photos/2026", true).unwrap();
    owner.create("/Photos/2026/janvier.txt", false).unwrap();
    owner
        .write("/Photos/2026/janvier.txt", 0, b"neige")
        .unwrap();
    owner.create("/prive.txt", false).unwrap();
    owner.write("/prive.txt", 0, b"secret").unwrap();
    owner.sync().unwrap();
    let e = owner.shared_element("/Photos").unwrap().unwrap();
    assert!(e.is_dir);
    assert!(owner.shared_element("/absent").unwrap().is_none());

    // Destinataire : le pointeur reçu, les blocs lus chez le Nœud du propriétaire.
    let store = Arc::new(Mutex::new(ShareStore::default()));
    store.lock().unwrap().received.push(ReceivedShare {
        id: "01".into(),
        pointer: Some(CachedPointer {
            name: e.name.clone(),
            is_dir: true,
            first_block_hash: hex::encode(e.first_block_hash),
            element_key: hex::encode(e.element_key),
            owner_label: "Alice".into(),
            node_addrs: vec!["/ip4/1.2.3.4/tcp/4001".into()],
            grant: "00".into(),
            grant_signature: "00".into(),
            ..Default::default()
        }),
        ..Default::default()
    });
    let fetched = Arc::new(Mutex::new(0usize));
    let f = fetched.clone();
    let src = owner_node.clone();
    let fetch: Fetch = Arc::new(move |_, _, _, h| {
        *f.lock().unwrap() += 1;
        src.get(h)
    });
    let mut bob = Drive::open(
        Arc::new(MemNode::default()),
        [7; 32],
        workspace("bob"),
        Arc::new(|| 1000),
    )
    .unwrap();
    bob.shared = Some(Arc::new(ReceivedTree::new(store.clone(), fetch)));
    let names = |d: &mut Drive, p: &str| {
        d.list(p)
            .unwrap()
            .into_iter()
            .map(|(n, _)| n)
            .collect::<Vec<_>>()
    };
    assert!(names(&mut bob, "/").contains(&"Partagés avec moi".to_string()));
    assert_eq!(
        names(&mut bob, SHARED_DIR),
        vec!["Alice — Photos".to_string()]
    );
    let root = format!("{SHARED_DIR}/Alice — Photos");
    let mut inside = names(&mut bob, &root);
    inside.sort();
    assert_eq!(inside, vec!["2026".to_string(), "vacances.txt".to_string()]);
    assert_eq!(
        bob.read(&format!("{root}/vacances.txt"), 0, 100).unwrap(),
        b"plage et soleil"
    );
    assert_eq!(
        bob.read(&format!("{root}/2026/janvier.txt"), 0, 100)
            .unwrap(),
        b"neige"
    );
    assert!(
        *fetched.lock().unwrap() > 0,
        "blocs lus chez le Nœud du propriétaire"
    );
    // Rien hors de l'élément partagé ; écriture refusée.
    assert!(bob
        .stat(&format!("{SHARED_DIR}/Alice — prive.txt"))
        .unwrap()
        .is_none());
    assert!(matches!(
        bob.create(&format!("{root}/nouveau.txt"), false),
        Err(DriveError::ReadOnly)
    ));
    assert!(matches!(
        bob.remove(&format!("{root}/vacances.txt")),
        Err(DriveError::ReadOnly)
    ));
    // Partage retiré par le propriétaire : il disparaît.
    store.lock().unwrap().received[0]
        .pointer
        .as_mut()
        .unwrap()
        .revoked = true;
    assert!(names(&mut bob, SHARED_DIR).is_empty());
}

#[test]
fn pointer_is_republished_when_the_element_changes_or_monthly() {
    let g = GivenShare {
        published_first: hex::encode([1; 32]),
        published_at: 100,
        ..Default::default()
    };
    assert!(!g.publish_due(Some(&[1; 32]), 200));
    assert!(g.publish_due(Some(&[2; 32]), 200), "nouvelle version");
    assert!(
        g.publish_due(Some(&[1; 32]), 100 + REPUBLISH_S),
        "republication"
    );
    let r = GivenShare {
        revoked: true,
        ..g.clone()
    };
    assert!(r.publish_due(None, 200), "retrait à publier");
    let done = GivenShare {
        revoke_done: true,
        ..r
    };
    assert!(!done.publish_due(None, 200));
}

#[test]
fn received_folder_name_survives_owner_rename() {
    let mut st = ShareStore::default();
    let p = CachedPointer {
        name: "Photos".into(),
        owner_label: "Alice".into(),
        ..Default::default()
    };
    st.received.push(ReceivedShare {
        folder: s3m_connector::shares::folder_name(&p),
        pointer: Some(CachedPointer {
            owner_label: "Alicia".into(),
            ..p
        }),
        ..Default::default()
    });
    assert_eq!(st.visible()[0].0, "Alice — Photos");
}
