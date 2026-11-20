//! `protocols.gestion-volumes` : vidage annulable, volume perdu, marqueur
//! signé, import d'un volume (intégrité et appartenance), validation du
//! brouillon, réponse à `OwnershipQuery`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use s3m_core::symmetric_suite::hash_sha256;
use s3m_node::chunk_store::{Id, Space};
use s3m_node::dispersal_engine::{DispersalState, Fabric, Reachable, StripeRec, UserDispersal};
use s3m_node::exchange::{pack_bits, unpack_bits, NodeService, UserAccount};
use s3m_node::volumes::{self, Change, ImportCounts, Inspection};
use s3m_node::{Owner, OwnerType, PhysicalStore, VolumeConfig, BLOCK_SIZE};
use s3m_protocol::exchange::{Body, Request, Response};

const NODE: [u8; 32] = [0x21; 32];
const OTHER: [u8; 32] = [0x22; 32];
const USER: [u8; 32] = [0x31; 32];
const PARTNER: [u8; 32] = [0x41; 32];

fn temp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("s3m-vol-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn pk(s: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(s)
        .verifying_key()
        .to_bytes()
}

fn block(i: u8) -> (Vec<u8>, Vec<u8>) {
    let data = vec![i; BLOCK_SIZE];
    (hash_sha256(&data).to_vec(), data)
}

fn vol(id: u32, path: &Path, cap: u64) -> VolumeConfig {
    VolumeConfig {
        volume_id: id,
        mount_path: path.to_path_buf(),
        max_capacity_bytes: cap,
    }
}

#[test]
fn draining_moves_every_block_and_can_be_cancelled() {
    let d = temp("drain");
    let (a, b) = (d.join("a"), d.join("b"));
    let mut s = PhysicalStore::open(d.join("db.sqlite"), vec![vol(1, &a, 1 << 40)]).unwrap();
    let owner = Owner::new(OwnerType::AttachedUser, USER.to_vec()).unwrap();
    let blocks: Vec<_> = (1..=10).map(block).collect();
    for (h, data) in &blocks {
        s.write_block(&owner, h, data).unwrap();
    }
    s.add_volume(vol(2, &b, 1 << 40)).unwrap();
    s.set_draining(1, true).unwrap();
    // Annulation à mi-parcours : les blocs déplacés restent valides.
    volumes::drain_step(&mut s, 1, 4).unwrap();
    s.set_draining(1, false).unwrap();
    let u = s.volume_usage();
    assert_eq!(u.iter().map(|v| v.blocks).sum::<usize>(), 10);
    assert_eq!(u[1].blocks, 4, "4 blocs déjà sur le volume 2");
    for (h, data) in &blocks {
        assert_eq!(s.read_block(h).unwrap().as_deref(), Some(&data[..]));
    }
    // Vidage complet, plus aucune allocation sur le volume vidé.
    s.set_draining(1, true).unwrap();
    while volumes::drain_step(&mut s, 1, 3).unwrap() > 0 {}
    let (h, data) = block(11);
    s.write_block(&owner, &h, &data).unwrap();
    let u = s.volume_usage();
    assert_eq!((u[0].blocks, u[0].containers, u[1].blocks), (0, 0, 11));
    for (h, data) in blocks.iter().chain([(h, data)].iter()) {
        assert_eq!(s.read_block(h).unwrap().as_deref(), Some(&data[..]));
    }
    s.remove_volume(1).unwrap();
    assert!(
        s.remove_volume(2).is_err(),
        "un volume non vide ne se retire pas"
    );
    // Réouverture : l'état persistant est cohérent.
    drop(s);
    let s = PhysicalStore::open(d.join("db.sqlite"), vec![vol(2, &b, 1 << 40)]).unwrap();
    assert_eq!(s.volume_usage()[0].blocks, 11);
}

#[test]
fn a_lost_volume_is_forgotten_and_reports_its_blocks() {
    let d = temp("lost");
    let mut s =
        PhysicalStore::open(d.join("db.sqlite"), vec![vol(1, &d.join("a"), 1 << 40)]).unwrap();
    let owner = Owner::new(OwnerType::Partner, PARTNER.to_vec()).unwrap();
    let (h, data) = block(7);
    s.write_block(&owner, &h, &data).unwrap();
    s.add_volume(vol(2, &d.join("b"), 1 << 40)).unwrap();
    let lost = s.forget_volume(1).unwrap();
    assert_eq!(lost.len(), 1);
    assert_eq!(lost[0].0.owner_type, OwnerType::Partner);
    assert_eq!(lost[0].1, vec![h.clone()]);
    assert!(s.read_block(&h).unwrap().is_none());
    assert_eq!(s.volume_usage().len(), 1);
}

#[test]
fn marker_tells_own_foreign_and_unmarked_disks_apart() {
    let d = temp("marker");
    assert_eq!(volumes::inspect(&d, &pk(&NODE)), Inspection::Empty);
    volumes::write_marker(&d, &NODE, 3).unwrap();
    assert!(volumes::read_marker(&d).is_some());
    assert_eq!(
        volumes::inspect(&d, &pk(&NODE)),
        Inspection::Mine {
            volume_id: 3,
            blocks: false
        }
    );
    assert!(matches!(
        volumes::inspect(&d, &pk(&OTHER)),
        Inspection::Foreign { .. }
    ));
    // Marqueur falsifié : refusé comme étranger.
    let m = std::fs::read_to_string(d.join(volumes::MARKER_FILE))
        .unwrap()
        .replace("\"volume_id\": 3", "\"volume_id\": 4");
    std::fs::write(d.join(volumes::MARKER_FILE), m).unwrap();
    assert!(matches!(
        volumes::inspect(&d, &pk(&NODE)),
        Inspection::Foreign { .. }
    ));
    volumes::wipe(&d).unwrap();
    std::fs::create_dir_all(d.join("blocks/0/aa")).unwrap();
    assert_eq!(volumes::inspect(&d, &pk(&NODE)), Inspection::Unmarked);
    volumes::wipe(&d).unwrap();
    assert_eq!(volumes::inspect(&d, &pk(&NODE)), Inspection::Empty);
}

/// Partenaire fictif : ne reconnaît que les hashes de `owned`.
struct FakeFabric {
    owned: Vec<Id>,
    reachable: bool,
}

#[async_trait::async_trait]
impl Fabric for FakeFabric {
    fn partners(&self) -> Vec<Reachable> {
        vec![]
    }
    async fn store(&self, _: &Id, _: Vec<u8>) -> Result<Vec<u8>, String> {
        Err("non".into())
    }
    async fn tombstone(
        &self,
        _: &Id,
        _: &s3m_node::tombstones::TombstoneNotice,
    ) -> Result<u64, String> {
        Err("non".into())
    }
    async fn publish(&self, _: Vec<u8>, _: Vec<u8>) -> Result<(), String> {
        Ok(())
    }
    async fn request(&self, partner: &Id, req: Request) -> Result<Response, String> {
        assert_eq!(partner, &PARTNER);
        if !self.reachable {
            return Err("injoignable".into());
        }
        let Body::OwnershipQuery { hashes } = req.body else {
            return Err("inattendu".into());
        };
        let bits: Vec<bool> = hashes
            .chunks(32)
            .map(|h| self.owned.iter().any(|o| o[..] == h[..]))
            .collect();
        Ok(Response::OwnershipAnswer {
            owned: pack_bits(&bits),
        })
    }
}

#[tokio::test]
async fn importing_a_volume_keeps_only_verified_blocks() {
    let d = temp("import");
    let disk = d.join("disk");
    // Ancienne installation : blocs d'un Utilisateur, d'un partenaire, d'un
    // dépôt de secours, sur le disque.
    {
        let mut old =
            PhysicalStore::open(d.join("old.sqlite"), vec![vol(1, &disk, 1 << 40)]).unwrap();
        let user = Owner::new(OwnerType::AttachedUser, USER.to_vec()).unwrap();
        let partner = Owner::new(OwnerType::Partner, PARTNER.to_vec()).unwrap();
        let rescue = Owner::new(OwnerType::EmergencyDepositor, OTHER.to_vec()).unwrap();
        for i in 1..=3 {
            let (h, b) = block(i);
            old.write_block(&user, &h, &b).unwrap();
        }
        for i in 11..=13 {
            let (h, b) = block(i);
            old.write_block(&partner, &h, &b).unwrap();
        }
        let (h, b) = block(21);
        old.write_block(&rescue, &h, &b).unwrap();
    }
    // Réinstallation : base neuve sur un autre volume, disque ajouté ensuite.
    let fresh =
        PhysicalStore::open(d.join("new.sqlite"), vec![vol(1, &d.join("main"), 1 << 40)]).unwrap();
    let mut svc = NodeService::with_store(NODE, Box::new(fresh));
    svc.users.insert(
        USER,
        UserAccount {
            salt: vec![0; 16],
            quota_bytes: 1 << 30,
            used_bytes: 0,
            root: [0; 32],
        },
    );
    svc.partners.entry(PARTNER).or_default();
    svc.store
        .physical()
        .unwrap()
        .add_volume(vol(2, &disk, 1 << 40))
        .unwrap();
    let service = Arc::new(Mutex::new(svc));
    // Registre de dispersion : blocs 1 et 2 de l'Utilisateur (le 3 est inconnu).
    let mut state = DispersalState::default();
    state.users.insert(
        hex::encode(USER),
        UserDispersal {
            pending: vec![hex::encode(block(1).0)],
            stripes: vec![StripeRec {
                data: vec![hex::encode(block(2).0)],
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    let dispersal = tokio::sync::Mutex::new(state);
    assert!(volumes::start_import(&disk, 1).unwrap().is_some());
    // Partenaire injoignable : rien n'est supprimé, nouvel essai plus tard.
    let mut counts = ImportCounts::default();
    let off = FakeFabric {
        owned: vec![],
        reachable: false,
    };
    assert!(!volumes::import_step(&service, &dispersal, &off, &disk, &mut counts).await);
    assert_eq!(counts.waiting, vec![hex::encode(PARTNER)]);
    // Le partenaire reconnaît 11 et 12, pas 13 (bilan cumulé sur les tours).
    let on = FakeFabric {
        owned: [11u8, 12]
            .map(|i| <Id>::try_from(&block(i).0[..]).unwrap())
            .to_vec(),
        reachable: true,
    };
    assert!(volumes::import_step(&service, &dispersal, &on, &disk, &mut counts).await);
    assert_eq!(counts.kept, 4, "{counts:?}");
    assert_eq!(
        counts.removed, 3,
        "3 et 13 inconnus, dépôt de secours : {counts:?}"
    );
    let s = service.lock().unwrap();
    for i in [1u8, 2, 11, 12] {
        assert!(
            s.store.contains(&<Id>::try_from(&block(i).0[..]).unwrap()),
            "bloc {i}"
        );
    }
    for i in [3u8, 13, 21] {
        assert!(
            !s.store.contains(&<Id>::try_from(&block(i).0[..]).unwrap()),
            "bloc {i}"
        );
    }
    assert!(
        volumes::import_dirs(&disk).is_empty(),
        "conteneurs importés effacés"
    );
}

#[test]
fn the_draft_is_validated_as_a_whole() {
    let d = temp("draft");
    let usage = vec![s3m_node::VolumeUsage {
        volume_id: 1,
        mount_path: d.join("a"),
        max_capacity_bytes: 10 << 30,
        used_bytes: 4 << 30,
        containers: 1,
        blocks: 100,
        draining: false,
    }];
    let id = pk(&NODE);
    // Dernier volume actif : refusé ; avec un ajout assez grand : accepté.
    let remove = Change::Remove { volume_id: 1 };
    assert!(volumes::validate(std::slice::from_ref(&remove), &usage, &id).is_err());
    let small = Change::Add {
        path: d.join("b").display().to_string(),
        capacity_bytes: 1 << 30,
        wipe: false,
    };
    assert!(volumes::validate(&[small, remove.clone()], &usage, &id)
        .unwrap_err()
        .contains("place insuffisante"));
    let big = Change::Add {
        path: d.join("c").display().to_string(),
        capacity_bytes: 8 << 30,
        wipe: false,
    };
    assert!(volumes::validate(&[big.clone(), remove.clone()], &usage, &id).is_ok());
    // Disque d'un autre Nœud : seulement « effacer et réutiliser ».
    let foreign = d.join("f");
    volumes::write_marker(&foreign, &OTHER, 1).unwrap();
    let add = |wipe| Change::Add {
        path: foreign.display().to_string(),
        capacity_bytes: 1 << 30,
        wipe,
    };
    assert!(volumes::validate(&[add(false)], &usage, &id)
        .unwrap_err()
        .contains("autre Nœud"));
    assert!(volumes::validate(&[add(true)], &usage, &id).is_ok());
    // Capacité sous l'occupation, doublon, effacement d'un volume plein.
    let shrink = Change::Edit {
        volume_id: 1,
        path: None,
        capacity_bytes: Some(1 << 30),
    };
    assert!(volumes::validate(&[shrink], &usage, &id).is_err());
    assert!(volumes::validate(
        &[big, remove.clone(), Change::Lost { volume_id: 1 }],
        &usage,
        &id
    )
    .is_err());
    assert!(volumes::validate(&[Change::Wipe { volume_id: 1 }], &usage, &id).is_err());
}

#[test]
fn ownership_query_answers_only_for_fragments_placed_at_the_requester() {
    let mut svc = NodeService::new(NODE);
    let mine: Id = [5; 32];
    let check: s3m_node::exchange::PlacementCheck = Arc::new(move |p, hashes| {
        Some(hashes.iter().map(|h| *p == PARTNER && *h == mine).collect())
    });
    let ask = |svc: &mut NodeService, from: Option<Id>| {
        svc.handle(
            b"x",
            from,
            b"y",
            Request {
                credential: None,
                body: Body::OwnershipQuery {
                    hashes: [mine, [6; 32]].concat(),
                },
            },
            1,
        )
    };
    // Sans registre disponible : réessayer plus tard (jamais « non »).
    assert!(matches!(ask(&mut svc, Some(PARTNER)), Response::Failure(_)));
    svc.placements = Some(check);
    let Response::OwnershipAnswer { owned } = ask(&mut svc, Some(PARTNER)) else {
        panic!()
    };
    assert_eq!(unpack_bits(&owned, 2), vec![true, false]);
    assert!(
        matches!(ask(&mut svc, None), Response::Failure(_)),
        "réservé aux Nœuds"
    );
    // Registre de dispersion : parité placée chez ce partenaire.
    let mut state = DispersalState::default();
    state.users.insert(
        hex::encode(USER),
        UserDispersal {
            stripes: vec![StripeRec {
                parity: vec![(0, hex::encode(mine), hex::encode(PARTNER))],
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    assert_eq!(
        volumes::placed_with(&state, &PARTNER, &[mine, [6; 32]]),
        vec![true, false]
    );
    assert_eq!(volumes::placed_with(&state, &OTHER, &[mine]), vec![false]);
    let _ = Space::Fragment;
}
