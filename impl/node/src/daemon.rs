//! Exécutable du Nœud — id `deploiement.packaging` (partie node).
//! Réf. spec : docs/07-deploiement/packaging.md.
//!
//! Assemble : identité depuis la phrase de récupération, stockage physique,
//! adaptateur DHT, serveur d'échange de blocs, état persistant (JSON),
//! tâches périodiques (pointeurs de migration, purge des Nœuds silencieux,
//! sauvegarde) et API locale du dashboard.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use libp2p::Multiaddr;
use p2p_storage_core::identity_derivation::{derive_identity_seed, mnemonic_to_seed, IdentityRole};
use p2p_storage_protocol::exchange::{
    decode_request, encode_request, Body, Delegation, Request, SILENT_NODE_RETENTION_SECONDS,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::dht_directory::{chiavdf_verifier, system_clock, DhtConfig, DhtNode};
use crate::exchange::{refresh_successors, BlockServer, NodeService, PartnerState, UserAccount};
use crate::local_http::{self, ActionFn, Asset, StatusFn};
use crate::tombstones::PartnerLedger;
use crate::{PhysicalStore, VolumeConfig};

/// Erreurs de l'exécutable.
#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("configuration : {0}")]
    Config(String),
    #[error("E/S : {0}")]
    Io(#[from] std::io::Error),
    #[error("démarrage : {0}")]
    Start(String),
}

/// Volume de stockage déclaré.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeSpec {
    pub volume_id: u32,
    pub mount_path: PathBuf,
    pub max_capacity_bytes: u64,
}

/// Fichier de configuration (JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Fichier contenant la phrase de récupération (BIP-39) du Nœud.
    pub seed_file: PathBuf,
    #[serde(default)]
    pub identity_index: u32,
    /// Répertoire de la base SQLite et de l'état.
    pub data_dir: PathBuf,
    pub volumes: Vec<VolumeSpec>,
    pub dht_listen: String,
    pub blocks_listen: String,
    #[serde(default)]
    pub bootstrap: Vec<String>,
    #[serde(default = "default_api_port")]
    pub api_port: u16,
}

fn default_api_port() -> u16 {
    8765
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, DaemonError> {
        let s = std::fs::read_to_string(path)?;
        let mut c: Config =
            serde_json::from_str(&s).map_err(|e| DaemonError::Config(e.to_string()))?;
        // Chemins relatifs : relatifs au fichier de configuration.
        let base = path.parent().unwrap_or(Path::new("."));
        let abs = |p: &mut PathBuf| {
            if p.is_relative() {
                *p = base.join(&*p);
            }
        };
        abs(&mut c.seed_file);
        abs(&mut c.data_dir);
        for v in &mut c.volumes {
            abs(&mut v.mount_path);
        }
        Ok(c)
    }
}

/// Graine `priv_node` depuis la phrase de récupération.
pub fn node_seed_from_mnemonic(mnemonic: &str, index: u32) -> Result<[u8; 32], DaemonError> {
    let words = mnemonic.split_whitespace().collect::<Vec<_>>().join(" ");
    bip39::Mnemonic::parse_normalized(&words)
        .map_err(|e| DaemonError::Config(format!("phrase de récupération : {e}")))?;
    let seed = mnemonic_to_seed(&words, "").map_err(|e| DaemonError::Config(e.to_string()))?;
    derive_identity_seed(&seed, IdentityRole::Node, index)
        .map_err(|e| DaemonError::Config(e.to_string()))
}

/// Nouvelle phrase de récupération de 24 mots.
pub fn generate_mnemonic() -> Result<String, DaemonError> {
    let mut entropy = [0u8; 32];
    getrandom::getrandom(&mut entropy).map_err(|e| DaemonError::Start(e.to_string()))?;
    bip39::Mnemonic::from_entropy(&entropy)
        .map(|m| m.to_string())
        .map_err(|e| DaemonError::Start(e.to_string()))
}

// --------------------------------------------------------- état persistant

fn hx(b: &[u8]) -> String {
    hex::encode(b)
}

fn unhex32(s: &str) -> Result<[u8; 32], String> {
    hex::decode(s)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "32 octets attendus".to_string())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SavedUser {
    pub user_id: String,
    pub salt: String,
    pub quota_bytes: u64,
    pub used_bytes: u64,
    pub root: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SavedPartner {
    pub node_id: String,
    #[serde(default)]
    pub addr: Option<String>,
    pub allowance: u64,
    pub hosted_for_partner: u64,
    pub hosted_by_partner: u64,
    pub last_tombstone_at: u64,
    pub last_seen: u64,
}

/// État du service hors blocs (les blocs sont dans le stockage physique).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SavedState {
    pub users: Vec<SavedUser>,
    pub partners: Vec<SavedPartner>,
    pub previous_node_ids: Vec<String>,
    pub incidents: Vec<String>,
    /// Délégations reçues, encodées comme requêtes `Delegate`.
    pub delegations: Vec<String>,
}

impl SavedState {
    pub fn capture(s: &NodeService, addrs: &HashMap<[u8; 32], String>) -> Self {
        let mut users: Vec<SavedUser> = s
            .users
            .iter()
            .map(|(id, u)| SavedUser {
                user_id: hx(id),
                salt: hx(&u.salt),
                quota_bytes: u.quota_bytes,
                used_bytes: u.used_bytes,
                root: hx(&u.root),
            })
            .collect();
        users.sort_by(|a, b| a.user_id.cmp(&b.user_id));
        let mut partners: Vec<SavedPartner> = s
            .partners
            .iter()
            .map(|(id, p)| SavedPartner {
                node_id: hx(id),
                addr: addrs.get(id).cloned(),
                allowance: p.allowance,
                hosted_for_partner: p.ledger.hosted_for_partner,
                hosted_by_partner: p.ledger.hosted_by_partner,
                last_tombstone_at: p.ledger.last_tombstone_at,
                last_seen: p.last_seen,
            })
            .collect();
        partners.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        Self {
            users,
            partners,
            previous_node_ids: s.previous_node_ids.iter().map(|i| hx(i)).collect(),
            incidents: s.incidents.iter().map(|i| hx(i)).collect(),
            delegations: s
                .delegations
                .iter()
                .map(|d| {
                    hx(&encode_request(&Request {
                        credential: None,
                        body: Body::Delegate(d.clone()),
                    }))
                })
                .collect(),
        }
    }

    /// Restaure dans `s` ; rend les adresses des partenaires.
    pub fn restore(&self, s: &mut NodeService) -> Result<HashMap<[u8; 32], String>, String> {
        let mut addrs = HashMap::new();
        for u in &self.users {
            s.users.insert(
                unhex32(&u.user_id)?,
                UserAccount {
                    salt: hex::decode(&u.salt).map_err(|e| e.to_string())?,
                    quota_bytes: u.quota_bytes,
                    used_bytes: u.used_bytes,
                    root: unhex32(&u.root)?,
                },
            );
        }
        for p in &self.partners {
            let id = unhex32(&p.node_id)?;
            if let Some(a) = &p.addr {
                addrs.insert(id, a.clone());
            }
            s.partners.insert(
                id,
                PartnerState {
                    allowance: p.allowance,
                    ledger: PartnerLedger {
                        hosted_for_partner: p.hosted_for_partner,
                        hosted_by_partner: p.hosted_by_partner,
                        last_tombstone_at: p.last_tombstone_at,
                    },
                    last_seen: p.last_seen,
                },
            );
        }
        s.previous_node_ids = self
            .previous_node_ids
            .iter()
            .map(|i| unhex32(i))
            .collect::<Result<_, _>>()?;
        s.incidents = self
            .incidents
            .iter()
            .map(|i| unhex32(i))
            .collect::<Result<_, _>>()?;
        s.delegations = self
            .delegations
            .iter()
            .map(|d| {
                let bytes = hex::decode(d).map_err(|e| e.to_string())?;
                match decode_request(&bytes).map_err(|e| e.to_string())?.body {
                    Body::Delegate(d) => Ok::<Delegation, String>(d),
                    _ => Err("délégation attendue".into()),
                }
            })
            .collect::<Result<_, _>>()?;
        Ok(addrs)
    }
}

/// Lecture de l'état (absent : état vide).
pub fn load_state(path: &Path) -> Result<SavedState, DaemonError> {
    match std::fs::read_to_string(path) {
        Ok(s) => serde_json::from_str(&s).map_err(|e| DaemonError::Config(e.to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(SavedState::default()),
        Err(e) => Err(e.into()),
    }
}

/// Écriture atomique (fichier temporaire puis renommage).
pub fn save_state(path: &Path, st: &SavedState) -> Result<(), DaemonError> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(st).expect("sérialisable"))?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

// ------------------------------------------------------------- dashboard

const ASSETS: &[Asset] = &[
    (
        "index.html",
        "text/html; charset=utf-8",
        include_str!("../dashboard/index.html"),
    ),
    (
        "app.js",
        "text/javascript; charset=utf-8",
        include_str!("../dashboard/app.js"),
    ),
];

/// Contexte partagé par le dashboard et les tâches.
pub struct Shared {
    pub service: Arc<Mutex<NodeService>>,
    pub addrs: Mutex<HashMap<[u8; 32], String>>,
    pub config: Config,
    pub peer_id: String,
    pub blocks_addr: Option<String>,
    pub dht_addr: Option<String>,
}

/// État présenté par le dashboard Nœud.
pub fn status(sh: &Shared, now: u64) -> Value {
    let s = sh.service.lock().unwrap();
    let addrs = sh.addrs.lock().unwrap();
    let mut users: Vec<Value> = s
        .users
        .iter()
        .map(|(id, u)| {
            json!({ "utilisateur": hx(id), "quota (octets)": u.quota_bytes,
                    "utilisé (octets)": u.used_bytes, "racine": hx(&u.root) })
        })
        .collect();
    users.sort_by_key(|v| v["utilisateur"].to_string());
    let mut partners: Vec<Value> = s
        .partners
        .iter()
        .map(|(id, p)| {
            let purge = p.last_seen + SILENT_NODE_RETENTION_SECONDS;
            json!({ "nœud": hx(id), "adresse": addrs.get(id),
                    "solde autorisé": p.allowance,
                    "hébergés chez lui": p.ledger.hosted_for_partner,
                    "hébergés pour lui": p.ledger.hosted_by_partner,
                    "dernier échange": p.last_seen,
                    "purge à venir": if p.last_seen == 0 { Value::Null } else { json!(purge) },
                    "purge échue": p.last_seen != 0 && purge <= now })
        })
        .collect();
    partners.sort_by_key(|v| v["nœud"].to_string());
    let volumes: Vec<Value> = sh
        .config
        .volumes
        .iter()
        .map(|v| json!({ "volume": v.volume_id, "chemin": v.mount_path, "capacité (octets)": v.max_capacity_bytes }))
        .collect();
    json!({
        "titre": "Nœud P2P-Storage",
        "identité": {
            "node_id": hx(&s.node_id()),
            "peer_id": sh.peer_id,
            "échange de blocs": sh.blocks_addr,
            "DHT": sh.dht_addr,
            "heure (s)": now,
        },
        "volumes": volumes,
        "utilisateurs rattachés": users,
        "partenaires": partners,
        "alertes d'intégrité signalées": s.incidents.iter().map(|i| hx(i)).collect::<Vec<_>>(),
        "migration": {
            "anciens node_id couverts": s.previous_node_ids.iter().map(|i| hx(i)).collect::<Vec<_>>(),
            "délégations reçues": s.delegations.len(),
            "pointeurs de migration connus": s.successors.len(),
        },
        "non suivi par cet exécutable": [
            "liste noire", "taux de republication DHT", "espace de secours"
        ],
        "actions": [
            { "nom": "attach_user", "libellé": "Rattacher un utilisateur",
              "champs": ["user_id", "salt", "quota_bytes"] },
            { "nom": "add_partner", "libellé": "Ajouter un partenaire",
              "champs": ["node_id", "addr", "allowance"] }
        ]
    })
}

fn field<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    v.get(k)
        .and_then(Value::as_str)
        .ok_or(format!("champ « {k} » manquant"))
}

fn number(v: &Value, k: &str) -> Result<u64, String> {
    match v.get(k) {
        Some(Value::Number(n)) => n.as_u64().ok_or(format!("« {k} » invalide")),
        Some(Value::String(s)) => s.trim().parse().map_err(|_| format!("« {k} » invalide")),
        _ => Err(format!("champ « {k} » manquant")),
    }
}

/// Actions du dashboard Nœud.
pub fn act(sh: &Shared, name: &str, v: Value) -> Result<Value, String> {
    let mut s = sh.service.lock().unwrap();
    match name {
        "attach_user" => {
            let id = unhex32(field(&v, "user_id")?)?;
            let salt = hex::decode(field(&v, "salt")?).map_err(|e| e.to_string())?;
            if salt.len() != 16 {
                return Err("sel de 16 octets attendu".into());
            }
            let quota_bytes = number(&v, "quota_bytes")?;
            let e = s.users.entry(id).or_insert(UserAccount {
                salt: salt.clone(),
                quota_bytes,
                used_bytes: 0,
                root: [0; 32],
            });
            e.salt = salt;
            e.quota_bytes = quota_bytes;
        }
        "add_partner" => {
            let id = unhex32(field(&v, "node_id")?)?;
            let addr = field(&v, "addr")?;
            addr.parse::<Multiaddr>().map_err(|e| e.to_string())?;
            let allowance = number(&v, "allowance")?;
            s.partners.entry(id).or_default().allowance = allowance;
            sh.addrs.lock().unwrap().insert(id, addr.to_string());
        }
        _ => return Err(format!("action inconnue : {name}")),
    }
    drop(s);
    save(sh).map_err(|e| e.to_string())?;
    Ok(json!({ "ok": true }))
}

fn state_path(c: &Config) -> PathBuf {
    c.data_dir.join("state.json")
}

/// Sauvegarde l'état courant.
pub fn save(sh: &Shared) -> Result<(), DaemonError> {
    let st = SavedState::capture(&sh.service.lock().unwrap(), &sh.addrs.lock().unwrap());
    save_state(&state_path(&sh.config), &st)
}

/// Démarre le Nœud ; rend le contexte et l'URL du dashboard.
pub async fn start(config: Config) -> Result<(Arc<Shared>, String), DaemonError> {
    let start = |e: &dyn std::fmt::Display| DaemonError::Start(e.to_string());
    let mnemonic = std::fs::read_to_string(&config.seed_file)?;
    let seed = node_seed_from_mnemonic(&mnemonic, config.identity_index)?;
    std::fs::create_dir_all(&config.data_dir)?;
    let volumes = config
        .volumes
        .iter()
        .map(|v| VolumeConfig {
            volume_id: v.volume_id,
            mount_path: v.mount_path.clone(),
            max_capacity_bytes: v.max_capacity_bytes,
        })
        .collect();
    let store = PhysicalStore::open(config.data_dir.join("store.sqlite"), volumes)
        .map_err(|e| start(&e))?;
    let mut service = NodeService::with_store(seed, Box::new(store));
    let addrs = load_state(&state_path(&config))?
        .restore(&mut service)
        .map_err(DaemonError::Config)?;
    let service = Arc::new(Mutex::new(service));

    let parse = |s: &str| {
        s.parse::<Multiaddr>()
            .map_err(|e| DaemonError::Config(format!("{s} : {e}")))
    };
    let dht = DhtNode::start(DhtConfig {
        node_seed: seed,
        listen: parse(&config.dht_listen)?,
        bootstrap: config
            .bootstrap
            .iter()
            .map(|b| parse(b))
            .collect::<Result<_, _>>()?,
        vdf: chiavdf_verifier(),
        clock: system_clock(),
    })
    .await
    .map_err(|e| start(&e))?;
    let blocks = BlockServer::start(
        seed,
        parse(&config.blocks_listen)?,
        service.clone(),
        system_clock(),
    )
    .await
    .map_err(|e| start(&e))?;

    let shared = Arc::new(Shared {
        service,
        addrs: Mutex::new(addrs),
        peer_id: blocks.peer_id().to_string(),
        blocks_addr: blocks.listen_addr().await.map(|a| a.to_string()),
        dht_addr: dht.listen_addr().await.map(|a| a.to_string()),
        config: config.clone(),
    });

    let clock = system_clock();
    let st_fn: StatusFn = {
        let (sh, clock) = (shared.clone(), clock.clone());
        Arc::new(move || status(&sh, clock()))
    };
    let act_fn: ActionFn = {
        let sh = shared.clone();
        Arc::new(move |n, v| act(&sh, n, v))
    };
    let url = local_http::serve(config.api_port, st_fn, act_fn, ASSETS).await?;

    // Tâches périodiques : sauvegarde (30 s), pointeurs de migration (1 h),
    // purge des Nœuds silencieux (1 j). Le serveur et la DHT vivent avec elles.
    let sh = shared.clone();
    tokio::spawn(async move {
        let _keep = (dht, blocks);
        let mut tick: u64 = 0;
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            tick += 1;
            if tick.is_multiple_of(120) {
                let _ = refresh_successors(&sh.service, &_keep.0).await;
            }
            if tick.is_multiple_of(2880) {
                let now = clock();
                sh.service.lock().unwrap().purge_silent_partners(now);
            }
            if let Err(e) = save(&sh) {
                eprintln!("sauvegarde de l'état : {e}");
            }
        }
    });
    Ok((shared, url))
}
