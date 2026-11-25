//! Restauration d'un Nœud depuis sa seule seed — id
//! `deploiement.disaster-recovery` (partie node), étapes 2 à 4. Réf. spec :
//! docs/07-deploiement/disaster-recovery.md.
//!
//! 1. Lecture de sa propre entrée DHT Node, déchiffrement du pointeur de
//!    snapshot (`K_node_self`).
//! 2. Reconstruction du snapshot depuis k fragments chez les partenaires,
//!    déchiffrement (`K_node_snapshot`) : Utilisateurs, partenaires (solde
//!    accordé), liste noire. Adresses des partenaires relues dans leurs
//!    propres entrées DHT Node.
//! 3. Pour chaque Utilisateur : `K_attach` recalculé, entrée
//!    DispersalManifest, parcours de l'arbre d'index, reconstruction de
//!    chaque bloc de données depuis la parité — la copie locale intégrale
//!    est retrouvée, et l'état de dispersion avec elle.
//!
//! La racine courante de chaque Utilisateur n'est pas dans le NodeManifest :
//! sa prochaine validation (`CommitRoot`) est acceptée telle quelle
//! (`NodeService::adopt_next_root`).

use std::collections::HashMap;
use std::sync::Mutex;

use libp2p::multiaddr::Protocol;
use libp2p::{identity, Multiaddr, PeerId};
use s3m_core::erasure::{padding_block, reconstruct_data};
use s3m_core::k_attach::derive_k_attach_as_node;
use s3m_core::k_dispersal::derive_k_dispersal_content;
use s3m_core::symmetric_suite::hash_sha256;
use s3m_core::version::CURRENT_HEADER;
use s3m_protocol::dht::dispersal_dht_key;
use s3m_protocol::dispersal::{
    decode_index_node, decode_manifest, encode_root_pointer, open_dispersal_entry, Id, PartnerDesc,
    StripeDesc,
};
use s3m_protocol::exchange::{Body, Request, Response};
use s3m_protocol::fb::dht as fbd;
use s3m_protocol::index::open_index_node;
use s3m_protocol::snapshot::{
    decode_manifest as decode_snapshot, encode_pointer, open_node_entry_pointer, open_snapshot,
};

use crate::chunk_store::Space;
use crate::dht_directory::DhtNode;
use crate::dispersal_engine::{DispersalState, EngineConfig, StripeRec, UserDispersal};
use crate::exchange::{BlockServer, NodeService, UserAccount};

/// Bilan d'une restauration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    pub users: usize,
    pub partners: usize,
    pub stripes: usize,
    pub blocks: usize,
    pub errors: Vec<String>,
}

fn hx(b: &[u8]) -> String {
    hex::encode(b)
}

fn peer_of(node_id: &Id) -> Option<PeerId> {
    let pk = identity::ed25519::PublicKey::try_from_bytes(node_id).ok()?;
    Some(identity::PublicKey::from(pk).to_peer_id())
}

/// `ip/port` d'une entrée DHT Node (enveloppe vérifiée).
fn ip_port(envelope: &[u8]) -> Option<(String, u16)> {
    let env = flatbuffers::root::<fbd::DhtEnvelope>(envelope).ok()?;
    let e = fbd::root_as_node_entry(env.payload()?.bytes()).ok()?;
    Some((e.ip()?.to_string(), e.port()))
}

/// Adresse d'échange de blocs d'un Nœud : son entrée DHT, sinon la table.
async fn resolve_addr(
    dht: &DhtNode,
    node_id: &Id,
    fallback: Option<&PartnerDesc>,
) -> Option<String> {
    if let Some(env) = dht.get(node_id.to_vec()).await.ok().flatten() {
        if let Some(a) = crate::exchange::entry_multiaddrs(node_id, &env)
            .into_iter()
            .next()
        {
            return Some(a);
        }
    }
    let (ip, port) = match dht
        .get(node_id.to_vec())
        .await
        .ok()
        .flatten()
        .and_then(|e| ip_port(&e))
    {
        Some(x) => x,
        None => fallback.map(|p| (p.ip.clone(), p.port))?,
    };
    let ip: std::net::IpAddr = ip.parse().ok()?;
    let mut a = Multiaddr::empty();
    a.push(match ip {
        std::net::IpAddr::V4(v) => Protocol::Ip4(v),
        std::net::IpAddr::V6(v) => Protocol::Ip6(v),
    });
    a.push(Protocol::Tcp(port));
    a.push(Protocol::P2p(peer_of(node_id)?));
    Some(a.to_string())
}

struct Fetcher<'a> {
    server: &'a BlockServer,
    dht: &'a DhtNode,
    addrs: &'a Mutex<HashMap<Id, String>>,
    coef: usize,
    /// Partenaires vus dans les tables des catalogues (adresses de repli).
    seen: Mutex<HashMap<Id, PartnerDesc>>,
}

impl Fetcher<'_> {
    async fn addr(&self, node: &Id, desc: Option<&PartnerDesc>) -> Option<Multiaddr> {
        if let Some(a) = self.addrs.lock().unwrap().get(node) {
            return a.parse().ok();
        }
        let a = resolve_addr(self.dht, node, desc).await?;
        self.addrs.lock().unwrap().insert(*node, a.clone());
        a.parse().ok()
    }

    /// k blocs de données d'un stripe, depuis la parité (hash vérifié).
    async fn data(&self, s: &StripeDesc, table: &[PartnerDesc]) -> Result<Vec<Vec<u8>>, String> {
        {
            let mut seen = self.seen.lock().unwrap();
            for p in table {
                seen.entry(p.node_id).or_insert_with(|| p.clone());
            }
        }
        let k = s.k as usize;
        let mut shards: Vec<Option<Vec<u8>>> = vec![None; k * (1 + self.coef)];
        let mut have = 0;
        for b in &s.blocks {
            if (b.index as usize) < k && b.is_padding {
                shards[b.index as usize] = Some(padding_block());
                have += 1;
            }
        }
        for b in s.blocks.iter().filter(|b| b.index as usize >= k) {
            if have >= k {
                break;
            }
            let Some(p) = table.iter().find(|p| p.partner_id == b.partner_id) else {
                continue;
            };
            let Some(addr) = self.addr(&p.node_id, Some(p)).await else {
                continue;
            };
            let req = Request {
                credential: None,
                body: Body::FetchFragment {
                    hash: b.hash.to_vec(),
                },
            };
            if let Ok(Response::BlockData(d)) = self.server.request(addr, req).await {
                if hash_sha256(&d) == b.hash && (b.index as usize) < shards.len() {
                    shards[b.index as usize] = Some(d);
                    have += 1;
                }
            }
        }
        reconstruct_data(shards, k, self.coef)
            .map_err(|e| format!("stripe {}… : {e}", &hx(&s.stripe_id)[..12]))
    }
}

/// Enregistrement d'état d'un stripe relu.
fn record(s: &StripeDesc, table: &[PartnerDesc], data: &[Vec<u8>]) -> StripeRec {
    let k = s.k as usize;
    let node_of = |pid: u16| {
        table
            .iter()
            .find(|p| p.partner_id == pid)
            .map(|p| hx(&p.node_id))
            .unwrap_or_default()
    };
    let mut padding = vec![false; k];
    for b in s.blocks.iter().filter(|b| (b.index as usize) < k) {
        padding[b.index as usize] = b.is_padding;
    }
    StripeRec {
        id: hx(&s.stripe_id),
        data: data.iter().map(|d| hx(&hash_sha256(d))).collect(),
        padding,
        parity: s
            .blocks
            .iter()
            .filter(|b| b.index as usize >= k)
            .map(|b| (b.index, hx(&b.hash), node_of(b.partner_id)))
            .collect(),
        salt: s.encryption_salt.map(|x| hx(&x)),
    }
}

/// Accès au réseau d'une restauration.
pub struct Net<'a> {
    pub server: &'a BlockServer,
    pub dht: &'a DhtNode,
    pub cfg: &'a EngineConfig,
    pub addrs: &'a Mutex<HashMap<Id, String>>,
}

impl Net<'_> {
    fn fetcher(&self) -> Fetcher<'_> {
        Fetcher {
            server: self.server,
            dht: self.dht,
            addrs: self.addrs,
            coef: self.cfg.coef,
            seen: Mutex::new(HashMap::new()),
        }
    }
}

/// Étapes 3 à 5 : sauvegarde du Nœud (snapshot du NodeManifest). Rend les
/// Utilisateurs `(id, sel)` restaurés, `None` si aucune sauvegarde n'est
/// publiée pour cette seed.
pub async fn restore_snapshot(
    service: &Mutex<NodeService>,
    state: &mut DispersalState,
    net: &Net<'_>,
    now: u64,
) -> Result<Option<(Vec<(Id, Vec<u8>)>, usize)>, String> {
    let (priv_node, pub_node) = {
        let s = service.lock().unwrap();
        (s.priv_node(), s.node_id())
    };
    let Some(env) = net
        .dht
        .get(pub_node.to_vec())
        .await
        .map_err(|e| e.to_string())?
    else {
        return Ok(None);
    };
    let Some(pointer) = open_node_entry_pointer(&priv_node, &env).map_err(|e| e.to_string())?
    else {
        return Ok(None);
    };
    let f = net.fetcher();
    let frames = f.data(&pointer.stripe, &pointer.partners).await?;
    let manifest = decode_snapshot(
        &open_snapshot(&priv_node, &pointer.salt, &frames).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    {
        let mut s = service.lock().unwrap();
        for p in &manifest.partners {
            // Quota négocié repris ; la confiance repart de sa valeur initiale.
            let st = s.partners.entry(p.node_id).or_default();
            if st.quota == 0 {
                st.quota = p.allowance;
            }
        }
        for u in &manifest.users {
            // Racine sauvegardée et son descripteur : un appareil neuf
            // retrouve ses fichiers ; le Connecteur qui en a une plus
            // récente l'impose toujours (adoption).
            let root: [u8; 32] = u.root.as_slice().try_into().unwrap_or([0; 32]);
            s.users.entry(u.user_id).or_insert_with(|| UserAccount {
                salt: u.salt.clone(),
                quota_bytes: u.quota_bytes,
                used_bytes: 0,
                root,
            });
            if !u.root_seal.is_empty() {
                s.root_seals.insert(u.user_id, u.root_seal.clone());
            }
            s.adopt_next_root.insert(u.user_id);
        }
    }
    for (n, at, why) in &manifest.blacklist {
        state.upkeep.blacklist.insert(hx(n), (*at, why.clone()));
    }
    for p in &manifest.partners {
        f.addr(&p.node_id, None).await;
    }
    state.snapshot.pointer = Some(hx(&encode_pointer(&pointer)));
    let rec = record(&pointer.stripe, &pointer.partners, &frames);
    count_hosted(service, std::slice::from_ref(&rec));
    state.snapshot.stripe = Some(rec);
    state.snapshot.last_at = now;
    Ok(Some((
        manifest
            .users
            .iter()
            .map(|u| (u.user_id, u.salt.clone()))
            .collect(),
        manifest.partners.len(),
    )))
}

/// Fragments confiés à chaque partenaire, recomptés depuis des stripes.
fn count_hosted(service: &Mutex<NodeService>, recs: &[StripeRec]) {
    let mut s = service.lock().unwrap();
    for rec in recs {
        for (_, _, p) in &rec.parity {
            if let Some(st) = hex::decode(p)
                .ok()
                .and_then(|v| <[u8; 32]>::try_from(v).ok())
                .map(|id| s.partners.entry(id).or_default())
            {
                st.ledger.hosted_for_partner += 1;
            }
        }
    }
}

/// Étape 6 : copie locale intégrale d'un Utilisateur (déjà dans
/// `service.users`) depuis la parité. Les blocs reçus entre-temps restent en
/// attente de dispersion. Rend `(stripes, blocs)`.
pub async fn restore_user(
    service: &Mutex<NodeService>,
    state: &mut DispersalState,
    net: &Net<'_>,
    user: Id,
    salt: &[u8],
    now: u64,
) -> Result<(usize, usize), String> {
    let priv_node = service.lock().unwrap().priv_node();
    let f = net.fetcher();
    let (mut d, blocks) = recover_user(service, &f, &priv_node, user, salt, now).await?;
    // Adresses des partenaires des catalogues (entrée DHT, sinon tables).
    let seen: Vec<PartnerDesc> = f.seen.lock().unwrap().values().cloned().collect();
    for p in &seen {
        f.addr(&p.node_id, Some(p)).await;
    }
    let recs: Vec<StripeRec> = d.stripes.iter().chain(&d.index).cloned().collect();
    count_hosted(service, &recs);
    if let Some(old) = state.users.remove(&hx(&user)) {
        d.pending = old.pending;
        d.pending_since = old.pending_since;
    }
    let stripes = d.stripes.len();
    state.users.insert(hx(&user), d);
    Ok((stripes, blocks))
}

/// Reprise à la reconnexion : vrai si une fiche de dispersion existe pour
/// cet Utilisateur sous `K_attach(ce Nœud, Utilisateur, sel)` — preuve
/// qu'il était rattaché à ce Nœud.
pub async fn was_attached(
    service: &Mutex<NodeService>,
    dht: &DhtNode,
    user: &Id,
    salt: &[u8],
) -> Result<bool, String> {
    let priv_node = service.lock().unwrap().priv_node();
    let k_attach = derive_k_attach_as_node(&priv_node, user, salt).map_err(|e| e.to_string())?;
    let Some(env) = dht
        .get(dispersal_dht_key(&k_attach).to_vec())
        .await
        .map_err(|e| e.to_string())?
    else {
        return Ok(false);
    };
    Ok(open_dispersal_entry(&k_attach, &env).is_ok())
}

/// Restaure le Nœud depuis le réseau en une fois (sauvegarde puis chaque
/// Utilisateur).
pub async fn recover(
    service: &Mutex<NodeService>,
    state: &mut DispersalState,
    server: &BlockServer,
    dht: &DhtNode,
    cfg: &EngineConfig,
    addrs: &Mutex<HashMap<Id, String>>,
    now: u64,
) -> Result<RecoveryReport, String> {
    let net = Net {
        server,
        dht,
        cfg,
        addrs,
    };
    let (users, partners) = restore_snapshot(service, state, &net, now)
        .await?
        .ok_or("aucune sauvegarde publiée pour cette seed")?;
    let mut report = RecoveryReport {
        users: users.len(),
        partners,
        ..Default::default()
    };
    for (u, salt) in users {
        match restore_user(service, state, &net, u, &salt, now).await {
            Ok((s, b)) => {
                report.stripes += s;
                report.blocks += b;
            }
            Err(e) => report.errors.push(format!("{}… : {e}", &hx(&u)[..16])),
        }
    }
    Ok(report)
}

/// Origine d'un Utilisateur à restaurer.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum UserOrigin {
    /// Listé dans la sauvegarde du Nœud.
    Snapshot,
    /// Repris à sa reconnexion (fiche de dispersion retrouvée).
    Reconnect,
}

/// Restauration d'un Utilisateur (étape 6).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UserRestore {
    pub salt: String,
    pub origin: UserOrigin,
    pub done_at: Option<u64>,
    pub stripes: usize,
    pub blocks: usize,
    pub tries: u32,
    pub error: Option<String>,
}

/// Issue des étapes 3 à 5.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SnapshotOutcome {
    Restored {
        users: usize,
        partners: usize,
    },
    /// Aucune sauvegarde publiée : Nœud neuf.
    Absent,
}

/// Délai sans entrée Node trouvée (Nœuds joints) avant de tenir le Nœud
/// pour neuf (`deploiement.disaster-recovery` § Restauration automatique).
pub const ABSENT_AFTER_S: u64 = 600;

/// État persistant de la restauration automatique (`restore.json`).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RestoreState {
    pub started_at: u64,
    /// Étape 2 : premier instant où des Nœuds ont été joints.
    pub peers_at: Option<u64>,
    /// Entrée Node introuvable depuis (Nœuds joints).
    pub absent_since: Option<u64>,
    /// Étapes 3 à 5.
    pub snapshot: Option<SnapshotOutcome>,
    pub snapshot_at: Option<u64>,
    /// Étape 6 : par Utilisateur (hex).
    pub users: std::collections::BTreeMap<String, UserRestore>,
    pub last_error: Option<String>,
    pub completed_at: Option<u64>,
    /// Reprises à la reconnexion seulement (installation existante) :
    /// jamais gelé.
    #[serde(default)]
    pub reconnect_only: bool,
}

impl RestoreState {
    /// Nœud gelé (aucune publication) : sauvegarde pas encore reprise.
    pub fn frozen(&self) -> bool {
        !self.reconnect_only && self.snapshot.is_none()
    }

    /// Utilisateurs dont la copie locale reste à reconstruire.
    pub fn pending_users(&self) -> Vec<(Id, Vec<u8>)> {
        self.users
            .iter()
            .filter(|(_, u)| u.done_at.is_none())
            .filter_map(|(id, u)| {
                Some((
                    hex::decode(id).ok()?.try_into().ok()?,
                    hex::decode(&u.salt).ok()?,
                ))
            })
            .collect()
    }

    pub fn add_user(&mut self, user: &Id, salt: &[u8], origin: UserOrigin) {
        self.users.entry(hx(user)).or_insert(UserRestore {
            salt: hx(salt),
            origin,
            done_at: None,
            stripes: 0,
            blocks: 0,
            tries: 0,
            error: None,
        });
        self.completed_at = None;
    }

    /// Tout est restauré : marque la fin.
    pub fn check_complete(&mut self, now: u64) {
        if !self.frozen()
            && self.users.values().all(|u| u.done_at.is_some())
            && self.completed_at.is_none()
        {
            self.completed_at = Some(now);
        }
    }
}

async fn recover_user(
    service: &Mutex<NodeService>,
    f: &Fetcher<'_>,
    priv_node: &[u8; 32],
    user: Id,
    salt: &[u8],
    now: u64,
) -> Result<(UserDispersal, usize), String> {
    let k_attach = derive_k_attach_as_node(priv_node, &user, salt).map_err(|e| e.to_string())?;
    let kdc = derive_k_dispersal_content(&k_attach).map_err(|e| e.to_string())?;
    let mut d = UserDispersal::default();
    let Some(env) = f
        .dht
        .get(dispersal_dht_key(&k_attach).to_vec())
        .await
        .map_err(|e| e.to_string())?
    else {
        return Ok((d, 0)); // rien encore dispersé pour cet Utilisateur
    };
    let pointer = open_dispersal_entry(&k_attach, &env).map_err(|e| e.to_string())?;
    let root = f.data(&pointer.root_stripe, &pointer.partners).await?;
    let clear = open_index_node(&kdc, &pointer.salt, &CURRENT_HEADER, &root[0])
        .map_err(|e| e.to_string())?;
    let manifest = decode_manifest(&clear).map_err(|e| e.to_string())?;
    let table = manifest.partners.clone();
    let mut index = vec![record(&pointer.root_stripe, &pointer.partners, &root)];
    let mut level = vec![manifest.root];
    let mut blocks = 0;
    while let Some(node) = level.pop() {
        for s in node.entries {
            let data = f.data(&s, &table).await?;
            if node.is_leaf {
                for (i, b) in data.iter().enumerate() {
                    if s.blocks
                        .iter()
                        .any(|x| x.index as usize == i && x.is_padding)
                    {
                        continue;
                    }
                    let h = hash_sha256(b);
                    let mut sv = service.lock().unwrap();
                    // Reprise après un échec : jamais compté deux fois.
                    let fresh = !sv.store.contains(&h);
                    sv.store
                        .put(Space::UserBlock, &user, &h, b)
                        .map_err(|e| e.to_string())?;
                    if let Some(acc) = sv.users.get_mut(&user).filter(|_| fresh) {
                        acc.used_bytes += b.len() as u64;
                    }
                    blocks += 1;
                }
                d.stripes.push(record(&s, &table, &data));
            } else {
                let salt = s.encryption_salt.ok_or("stripe d'index sans sel")?;
                let clear = open_index_node(&kdc, &salt, &CURRENT_HEADER, &data[0])
                    .map_err(|e| e.to_string())?;
                index.push(record(&s, &table, &data));
                level.push(decode_index_node(&clear).map_err(|e| e.to_string())?);
            }
        }
    }
    index.rotate_left(1); // racine en dernier
    d.index = index;
    d.pointer = Some(hx(&encode_root_pointer(&pointer)));
    d.published_at = now;
    d.next_republish = now;
    Ok((d, blocks))
}
