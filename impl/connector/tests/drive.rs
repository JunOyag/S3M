//! Moteur du lecteur monté (`protocols.acces-applicatif`,
//! `protocols.ecriture-differee`) sur un Nœud simulé en mémoire.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use s3m_connector::drive::*;
use s3m_connector::fs::BlockHash;

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
    let d = std::env::temp_dir().join(format!("p2p-drive-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn drive(node: &Arc<MemNode>, ws: &std::path::Path) -> Drive {
    Drive::open(node.clone(), [9; 32], ws.to_path_buf(), Arc::new(|| 1000)).unwrap()
}

fn names(d: &mut Drive, p: &str) -> Vec<String> {
    d.list(p).unwrap().into_iter().map(|(n, _)| n).collect()
}

#[test]
fn files_and_directories_survive_sync_and_are_read_back_from_the_node() {
    let node = Arc::new(MemNode::default());
    let ws = workspace("basic");
    let mut d = drive(&node, &ws);
    assert!(names(&mut d, "/").is_empty());
    d.create("/docs", true).unwrap();
    d.create("/docs/a.txt", false).unwrap();
    d.write("/docs/a.txt", 0, b"bonjour").unwrap();
    d.write("/docs/a.txt", 3, b"SOIR").unwrap();
    assert_eq!(d.read("/docs/a.txt", 0, 100).unwrap(), b"bonSOIR");
    let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    d.create("/big.bin", false).unwrap();
    d.write("/big.bin", 0, &big).unwrap();
    assert_eq!(d.sync().unwrap(), 3);
    assert_eq!(d.pending(), 0);
    assert_eq!(*node.root.lock().unwrap(), d.root_hash());

    // Relecture par un lecteur rouvert, cache local vidé : tout vient du Nœud.
    drop(d);
    std::fs::remove_dir_all(ws.join("cache")).unwrap();
    let mut d = drive(&node, &ws);
    assert_eq!(names(&mut d, "/"), vec!["big.bin", "docs"]);
    assert_eq!(d.read("/docs/a.txt", 0, 100).unwrap(), b"bonSOIR");
    assert_eq!(
        d.read("/big.bin", 65_000, 1000).unwrap(),
        big[65_000..66_000]
    );
    let m = d.stat("/big.bin").unwrap().unwrap();
    assert_eq!((m.is_dir, m.size), (false, 200_000));
    assert!(d.stat("/docs").unwrap().unwrap().is_dir);
}

#[test]
fn rename_delete_and_nested_edits_are_copy_on_write() {
    let node = Arc::new(MemNode::default());
    let ws = workspace("cow");
    let mut d = drive(&node, &ws);
    d.create("/a", true).unwrap();
    d.create("/a/b", true).unwrap();
    d.create("/a/b/f", false).unwrap();
    d.write("/a/b/f", 0, b"v1").unwrap();
    d.create("/x", false).unwrap();
    d.sync().unwrap();

    // Déplacement d'un répertoire distant non vide, puis modification dedans.
    // Destination sous un dossier inexistant ou un fichier : refus, rien ne bouge.
    assert!(matches!(d.rename("/x", "/nulle/part/x", false), Err(DriveError::NotFound)));
    assert!(matches!(d.rename("/a", "/x/a", false), Err(DriveError::NotADirectory)));
    assert!(d.stat("/x").unwrap().is_some() && d.stat("/a").unwrap().is_some());
    d.rename("/a", "/z", false).unwrap();
    assert!(d.stat("/a").unwrap().is_none());
    assert_eq!(d.read("/z/b/f", 0, 10).unwrap(), b"v1");
    d.write("/z/b/f", 2, b"+").unwrap();
    assert!(matches!(d.remove("/z/b"), Err(DriveError::NotEmpty)));
    d.remove("/x").unwrap();
    assert!(matches!(d.create("/z", true), Err(DriveError::Exists)));
    d.sync().unwrap();

    std::fs::remove_dir_all(ws.join("cache")).unwrap();
    let mut d = drive(&node, &ws);
    assert_eq!(names(&mut d, "/"), vec!["z"]);
    assert_eq!(d.read("/z/b/f", 0, 10).unwrap(), b"v1+");
    d.set_size("/z/b/f", 1).unwrap();
    d.rename("/z/b/f", "/z/g", false).unwrap();
    assert_eq!(names(&mut d, "/z"), vec!["b", "g"]);
    d.sync().unwrap();
    assert_eq!(d.read("/z/g", 0, 10).unwrap(), b"v");
    assert!(names(&mut d, "/z/b").is_empty());
}

#[test]
fn concurrent_root_change_is_a_conflict_and_keeps_local_changes() {
    let node = Arc::new(MemNode::default());
    let ws = workspace("conflict");
    let mut d = drive(&node, &ws);
    d.create("/f", false).unwrap();
    d.write("/f", 0, b"0123456789").unwrap();
    assert_eq!(d.pending_bytes(), 10, "taille des modifications en attente");
    *node.root.lock().unwrap() = [0xEE; 32];
    assert!(matches!(d.sync(), Err(DriveError::Conflict)));
    assert_eq!(d.conflict, Some([0xEE; 32]));
    assert_eq!(d.pending(), 1);
    // Journal persistant : les modifications survivent à un redémarrage.
    drop(d);
    let mut d = drive(&node, &ws);
    assert_eq!(d.pending(), 1);
    assert_eq!(names(&mut d, "/"), vec!["f"]);
}

/// Nœud simulé qu'on peut rendre injoignable.
#[derive(Default)]
struct FlakyNode {
    inner: MemNode,
    offline: std::sync::atomic::AtomicBool,
}

impl FlakyNode {
    fn down(&self) -> bool {
        self.offline.load(std::sync::atomic::Ordering::SeqCst)
    }
    fn set_down(&self, v: bool) {
        self.offline.store(v, std::sync::atomic::Ordering::SeqCst);
    }
}

impl BlockIo for FlakyNode {
    fn get(&self, h: &BlockHash) -> Option<Vec<u8>> {
        if self.down() {
            return None;
        }
        self.inner.get(h)
    }
    fn put(&self, h: &BlockHash, frame: Vec<u8>) -> Result<(), String> {
        if self.down() {
            return Err("injoignable".into());
        }
        self.inner.put(h, frame)
    }
    fn commit(&self, base: &BlockHash, new: &BlockHash) -> Result<Option<BlockHash>, String> {
        if self.down() {
            return Err("injoignable".into());
        }
        self.inner.commit(base, new)
    }
}

/// `protocols.espace-secours` : arborescence construite hors ligne
/// (répertoires relus dans le cache local), validée telle quelle au retour
/// du Nœud ; un autre lecteur adopte la racine réconciliée.
#[test]
fn emergency_tree_is_built_offline_and_committed_unchanged_on_return() {
    let node = Arc::new(FlakyNode::default());
    let ws = workspace("emergency");
    let mut d = Drive::open(node.clone(), [9; 32], ws.clone(), Arc::new(|| 1000)).unwrap();
    d.create("/docs", true).unwrap();
    d.create("/docs/a.txt", false).unwrap();
    d.write("/docs/a.txt", 0, b"avant").unwrap();
    d.sync().unwrap();
    let base = d.root_hash();
    // Parcours en ligne : les blocs de répertoire sont gardés en cache.
    assert_eq!(names(&mut d, "/docs"), vec!["a.txt"]);

    node.set_down(true);
    assert!(d.emergency_build().unwrap().is_none(), "rien en attente");
    d.create("/docs/b.txt", false).unwrap();
    d.write("/docs/b.txt", 0, b"pendant la panne").unwrap();
    assert!(d.sync().is_err());
    let b = d
        .emergency_build()
        .unwrap()
        .expect("arborescence construite hors ligne");
    assert_eq!(b.base, base);
    assert!(!b.blocks.is_empty());
    assert!(!d.emergency_current());
    d.emergency_confirm(&b).unwrap();
    assert!(d.emergency_current());
    assert!(d.emergency_build().unwrap().is_none(), "déjà déposé");

    // Retour du Nœud : la racine déposée est validée telle quelle.
    node.set_down(false);
    assert_eq!(d.sync().unwrap(), 1);
    assert_eq!(d.root_hash(), b.root.fs_root_hash);
    assert_eq!(*node.inner.root.lock().unwrap(), b.root.fs_root_hash);
    assert!(!d.emergency_current());

    // Autre lecteur, resté sur l'ancienne racine : adopte la racine réconciliée.
    let ws2 = workspace("emergency-other");
    let mut other = Drive::open(node.clone(), [9; 32], ws2, Arc::new(|| 1000)).unwrap();
    other
        .adopt_root(s3m_connector::access::Root {
            fs_root_hash: base,
            encryption_salt: [0; 16],
            key_version: 1,
        })
        .unwrap();
    assert!(
        !other.advance_root(&[7; 32], b.root.clone()).unwrap(),
        "autre base"
    );
    assert!(other.advance_root(&base, b.root.clone()).unwrap());
    assert_eq!(names(&mut other, "/docs"), vec!["a.txt", "b.txt"]);
    assert_eq!(
        other.read("/docs/b.txt", 0, 100).unwrap(),
        b"pendant la panne"
    );
}

/// Une modification après le dépôt l'invalide : la synchronisation
/// reconstruit normalement ; une racine déjà validée ailleurs n'est pas un
/// conflit.
#[test]
fn a_later_change_supersedes_the_emergency_tree() {
    let node = Arc::new(FlakyNode::default());
    let ws = workspace("emergency-later");
    let mut d = Drive::open(node.clone(), [9; 32], ws, Arc::new(|| 1000)).unwrap();
    d.create("/a.txt", false).unwrap();
    d.sync().unwrap();
    let _ = names(&mut d, "/");
    d.read("/a.txt", 0, 1).unwrap(); // contenu en cache local
    node.set_down(true);
    d.write("/a.txt", 0, b"1").unwrap();
    let b = d.emergency_build().unwrap().unwrap();
    d.emergency_confirm(&b).unwrap();
    d.write("/a.txt", 0, b"2").unwrap();
    assert!(!d.emergency_current());
    node.set_down(false);
    d.sync().unwrap();
    assert_ne!(d.root_hash(), b.root.fs_root_hash);
    assert_eq!(d.read("/a.txt", 0, 10).unwrap(), b"2");
}

/// Résolution d'un conflit (`protocols.write-queue#resolution-de-conflit`) :
/// la racine d'un autre appareil devient la base, les modifications locales
/// sont rejouées ; modifié des deux côtés, le plus récent gagne et l'autre
/// est gardé à côté.
#[test]
fn conflict_is_resolved_by_replaying_local_changes_on_the_new_root() {
    let node = Arc::new(MemNode::default());
    let open = |ws: &str, t: u64| {
        Drive::open(node.clone(), [9; 32], workspace(ws), Arc::new(move || t)).unwrap()
    };
    // Appareil A : état de départ partagé.
    let mut a = open("rebase-a", 1_000);
    for (p, c) in [
        ("/commun.txt", "départ"),
        ("/a.txt", "a"),
        ("/supprime.txt", "x"),
    ] {
        a.create(p, false).unwrap();
        a.write(p, 0, c.as_bytes()).unwrap();
    }
    a.sync().unwrap();
    // Appareil B, à jour, modifie plus tard (3 000) qu'A (2 000).
    let mut b = open("rebase-b", 3_000);
    assert!(b.adopt_root(a.root()).unwrap());
    b.set_size("/commun.txt", 0).unwrap();
    b.write("/commun.txt", 0, b"version B").unwrap();
    b.create("/b.txt", false).unwrap();
    b.write("/b.txt", 0, b"b").unwrap();
    b.remove("/supprime.txt").unwrap();
    // A écrit d'abord.
    let mut a2 = open("rebase-a2", 2_000);
    assert!(a2.adopt_root(a.root()).unwrap());
    a2.set_size("/commun.txt", 0).unwrap();
    a2.write("/commun.txt", 0, b"version A").unwrap();
    a2.create("/a2.txt", false).unwrap();
    a2.sync().unwrap();
    assert!(matches!(b.sync(), Err(DriveError::Conflict)));
    // 2026-11-23 13:10:43 UTC.
    let copies = b.rebase(a2.root(), 1_795_439_443).unwrap();
    assert_eq!(
        copies,
        vec!["/commun (conflit 2026-11-23 13h10).txt".to_string()]
    );
    b.sync().unwrap();
    // Un troisième appareil voit la fusion.
    let mut c = open("rebase-c", 4_000);
    assert!(c.adopt_root(b.root()).unwrap());
    let mut n = names(&mut c, "/");
    n.sort();
    assert_eq!(
        n,
        vec![
            "a.txt",
            "a2.txt",
            "b.txt",
            "commun (conflit 2026-11-23 13h10).txt",
            "commun.txt"
        ]
    );
    assert_eq!(
        c.read("/commun.txt", 0, 100).unwrap(),
        b"version B",
        "le plus récent gagne"
    );
    assert_eq!(
        c.read("/commun (conflit 2026-11-23 13h10).txt", 0, 100)
            .unwrap(),
        b"version A",
        "l'autre est gardé à côté"
    );

    // Nouvel espace local vide (changement de Nœud) avec un fichier : rejoué
    // sur la racine existante, sans copie.
    let mut fresh = open("rebase-fresh", 5_000);
    fresh.create("/logo.png", false).unwrap();
    fresh.write("/logo.png", 0, b"png").unwrap();
    assert!(matches!(fresh.sync(), Err(DriveError::Conflict)));
    assert!(fresh.rebase(b.root(), 5_000).unwrap().is_empty());
    fresh.sync().unwrap();
    assert!(names(&mut fresh, "/").contains(&"logo.png".to_string()));
    assert!(names(&mut fresh, "/").contains(&"b.txt".to_string()));
}

/// Libération des anciens blocs (`protocols.echange-blocs` § Libération) :
/// tout ce qui est annoncé libérable peut disparaître du Nœud sans que la
/// version courante cesse d'être lisible ; un élément déplacé garde ses
/// blocs.
#[test]
fn released_blocks_are_never_needed_by_the_new_root() {
    let node = Arc::new(MemNode::default());
    let ws = workspace("release");
    let mut d = drive(&node, &ws);
    let big: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    for (p, c) in [
        ("/garde.txt", b"garde".to_vec()),
        ("/modifie.txt", big.clone()),
        ("/supprime.txt", b"x".to_vec()),
        ("/deplace.txt", big.clone()),
    ] {
        d.create(p, false).unwrap();
        d.write(p, 0, &c).unwrap();
    }
    d.create("/dossier", true).unwrap();
    d.create("/dossier/a.txt", false).unwrap();
    d.write("/dossier/a.txt", 0, b"a").unwrap();
    d.sync().unwrap();
    assert!(
        d.pending_release(usize::MAX).is_empty(),
        "première version : rien à libérer"
    );
    let blocks_v1 = node.blocks.lock().unwrap().len();

    // Seconde version : modifié, supprimé, déplacé, dossier supprimé.
    d.write("/modifie.txt", 0, b"NOUVEAU").unwrap();
    d.remove("/supprime.txt").unwrap();
    d.rename("/deplace.txt", "/ailleurs.txt", false).unwrap();
    d.remove("/dossier/a.txt").unwrap();
    d.remove("/dossier").unwrap();
    d.sync().unwrap();
    let released = d.pending_release(usize::MAX);
    assert!(!released.is_empty());
    assert!(released.len() < blocks_v1);

    // Le Nœud efface tout ce qui est libéré : la version courante reste
    // entière pour un autre appareil.
    {
        let mut b = node.blocks.lock().unwrap();
        for h in &released {
            b.remove(h);
        }
    }
    let mut other = drive(&node, &workspace("release-lecteur"));
    assert!(other.adopt_root(d.root()).unwrap());
    let mut n = names(&mut other, "/");
    n.sort();
    assert_eq!(n, vec!["ailleurs.txt", "garde.txt", "modifie.txt"]);
    assert_eq!(other.read("/garde.txt", 0, 100).unwrap(), b"garde");
    assert_eq!(
        other.read("/ailleurs.txt", 0, big.len()).unwrap(),
        big,
        "déplacé : blocs gardés"
    );
    let m = other.read("/modifie.txt", 0, big.len()).unwrap();
    assert_eq!(&m[..7], b"NOUVEAU");
    assert_eq!(&m[7..], &big[7..]);

    // Accusé du Nœud : liste vidée.
    d.confirm_release(&released).unwrap();
    assert!(d.pending_release(usize::MAX).is_empty());
}
