//! Dispersion automatique par le Nœud — id
//! `protocols.dispersion-transactionnelle` (orchestration), avec
//! `protocols.erasure-coding` et `protocols.index-adaptatif`. Réf. spec :
//! docs/04-protocols/dispersion-transactionnelle.md § Orchestration.
//!
//! Un cycle, pour chaque Utilisateur rattaché :
//! 1. regroupe les blocs reçus en stripes de k (padding après le délai
//!    d'inactivité ; un stripe partiel est recréé dès l'arrivée de vrais
//!    blocs) ;
//! 2. calcule la parité et la place chez coef×k partenaires distincts
//!    (distance XOR au `stripe_id`), reçu signé exigé, au moins k+2 ;
//! 3. une fois tous les stripes de données confirmés, réémet l'arbre
//!    d'index de bas en haut (chaque nœud chiffré = bloc 0 d'un stripe
//!    d'index), puis la racine ;
//! 4. publie l'entrée DHT DispersalManifest (commit), la republie à son
//!    échéance, et purge par tombstones les fragments devenus orphelins
//!    après le délai de grâce.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use s3m_core::erasure::{encode_parity, padding_block};
use s3m_core::k_attach::derive_k_attach_as_node;
use s3m_core::k_dispersal::derive_k_dispersal_content;
use s3m_core::symmetric_suite::hash_sha256;
use s3m_core::version::CURRENT_HEADER;
use s3m_protocol::dht::{dispersal_dht_key, next_republish_at};
use s3m_protocol::dispersal::*;
use s3m_protocol::exchange::{verify_receipt, Body, Request};
use s3m_protocol::index::seal_index_node;
use serde::{Deserialize, Serialize};

use crate::chunk_store::Space;
use crate::exchange::NodeService;
use crate::tombstones::{apply_acknowledged, TombstoneNotice};

/// Blocs de données par stripe : constante du logiciel
/// (`protocols.erasure-coding#parametres`).
pub const K: usize = 4;
/// Coefficient de redondance (parité = coef×k) : constante du logiciel.
pub const COEF: usize = 3;

fn const_k() -> usize {
    K
}
fn const_coef() -> usize {
    COEF
}

/// Paramètres de dispersion. `k` et `coef` ne sont jamais lus ni écrits dans
/// la configuration : ils valent [`K`] et [`COEF`] (les tests seuls les
/// réduisent).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct EngineConfig {
    #[serde(skip, default = "const_k")]
    pub k: usize,
    #[serde(skip, default = "const_coef")]
    pub coef: usize,
    /// `duree_max_idle_seconds` : délai avant padding d'un paquet incomplet.
    pub idle_timeout_s: u64,
    /// Délai de grâce avant purge des fragments orphelins.
    pub grace_s: u64,
    /// Confirmations minimales par stripe : k + 2 (0 = k + 2), abaissable
    /// jusqu'à 1 pour des essais sur un réseau local de quelques Nœuds
    /// (`protocols.dispersion-transactionnelle`).
    #[serde(default)]
    pub min_confirmations: usize,
}

impl EngineConfig {
    /// Seuil de confirmation effectif, entre 1 et k + 2.
    pub fn min_confirmations(&self) -> usize {
        match self.min_confirmations {
            0 => self.k + 2,
            n => n.clamp(1, self.k + 2),
        }
    }
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            k: K,
            coef: COEF,
            idle_timeout_s: 300,
            grace_s: 3_600,
            min_confirmations: 0,
        }
    }
}

/// Partenaire joignable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reachable {
    pub node_id: Id,
    pub ip: String,
    pub port: u16,
}

/// Accès réseau du moteur (échange de blocs et DHT).
#[async_trait::async_trait]
pub trait Fabric: Send + Sync {
    fn partners(&self) -> Vec<Reachable>;
    /// Dépose un fragment ; rend la signature du reçu.
    async fn store(&self, partner: &Id, data: Vec<u8>) -> Result<Vec<u8>, String>;
    /// Envoie un avis de suppression ; rend le nombre de blocs libérés.
    async fn tombstone(&self, partner: &Id, notice: &TombstoneNotice) -> Result<u64, String>;
    async fn publish(&self, key: Vec<u8>, envelope: Vec<u8>) -> Result<(), String>;
    /// Requête quelconque à un partenaire (`Err` : injoignable).
    async fn request(
        &self,
        partner: &Id,
        req: Request,
    ) -> Result<s3m_protocol::exchange::Response, String>;
}

/// Requête `Tombstone` d'un avis.
pub fn tombstone_request(n: &TombstoneNotice) -> Request {
    Request {
        credential: None,
        body: Body::Tombstone {
            timestamp: n.timestamp,
            hashes: n.block_hashes.concat(),
            signature: n.signature.to_vec(),
        },
    }
}

// ------------------------------------------------------------------ état

fn hx(b: &[u8]) -> String {
    hex::encode(b)
}

fn id(s: &str) -> Id {
    hex::decode(s)
        .ok()
        .and_then(|v| v.try_into().ok())
        .unwrap_or([0; 32])
}

/// Stripe dispersé.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StripeRec {
    pub id: String,
    /// Hashes des k blocs de données.
    pub data: Vec<String>,
    pub padding: Vec<bool>,
    /// `(indice, hash, node_id du partenaire)` des fragments de parité placés.
    pub parity: Vec<(u16, String, String)>,
    /// Sel du nœud d'index encodé (stripes d'index seulement).
    pub salt: Option<String>,
}

/// Fragment à purger après le délai de grâce.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Retired {
    pub at: u64,
    pub hash: String,
    pub partner: String,
}

/// État de dispersion d'un Utilisateur.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserDispersal {
    /// Blocs reçus, pas encore dans un stripe.
    pub pending: Vec<String>,
    pub pending_since: u64,
    pub stripes: Vec<StripeRec>,
    /// Stripes de l'arbre d'index courant (racine en dernier).
    pub index: Vec<StripeRec>,
    pub retired: Vec<Retired>,
    /// Pointeur racine publié (sérialisé, hex).
    pub pointer: Option<String>,
    pub published_at: u64,
    pub next_republish: u64,
    /// Catalogue modifié depuis la dernière publication.
    pub dirty: bool,
    pub last_error: Option<String>,
}

/// État de dispersion du Nœud (persisté en JSON).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct DispersalState {
    pub users: BTreeMap<String, UserDispersal>,
    /// Dernier horodatage d'avis envoyé, par partenaire (anti-rejeu).
    pub last_tombstone: BTreeMap<String, u64>,
    /// Contrôles et réparation (`crate::upkeep`).
    #[serde(default)]
    pub upkeep: crate::upkeep::UpkeepState,
    /// Snapshot du NodeManifest (`crate::snapshot_engine`).
    #[serde(default)]
    pub snapshot: SnapshotRec,
    /// Partenariats automatiques (`crate::partnering`).
    #[serde(default)]
    pub partnering: crate::partnering::PartneringState,
}

/// Snapshot du NodeManifest dispersé.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotRec {
    /// SHA-256 du contenu (horodatage exclu) du dernier snapshot dispersé.
    pub digest: String,
    pub stripe: Option<StripeRec>,
    /// `NodeSnapshotPointer` sérialisé (hex).
    pub pointer: Option<String>,
    pub last_at: u64,
    pub retired: Vec<Retired>,
    pub last_error: Option<String>,
}

impl DispersalState {
    /// Blocs déjà connus (en attente ou dans un stripe) d'un Utilisateur.
    pub fn known(&self, user: &Id) -> std::collections::HashSet<String> {
        let mut s = std::collections::HashSet::new();
        if let Some(u) = self.users.get(&hx(user)) {
            s.extend(u.pending.iter().cloned());
            for st in &u.stripes {
                s.extend(st.data.iter().cloned());
            }
        }
        s
    }

    /// Fragments encore attendus chez leur partenaire `(hash, partenaire)` :
    /// stripes de données, d'index et du snapshot.
    pub fn referenced(&self) -> std::collections::HashSet<(String, String)> {
        let snap = self.snapshot.stripe.iter();
        self.users
            .values()
            .flat_map(|u| u.stripes.iter().chain(u.index.iter()))
            .chain(snap)
            .flat_map(|st| st.parity.iter().map(|(_, h, p)| (h.clone(), p.clone())))
            .collect()
    }

    /// Retire `node` (hex) de la liste noire ; il est aussi oublié de la
    /// recherche de partenaires, qui pourra le reproposer.
    pub fn unblacklist(&mut self, node: &str) -> bool {
        let found = self.upkeep.blacklist.remove(node).is_some();
        if found {
            self.partnering.peers.remove(node);
            // La rupture a effacé de part et d'autre les fragments échangés :
            // ceux qu'on croyait chez lui sont perdus. Oubliés, ils ne sont
            // plus challengés (sinon nouvelle « fraude ») et la réparation
            // les replace.
            let stripes = self
                .users
                .values_mut()
                .flat_map(|u| u.stripes.iter_mut().chain(u.index.iter_mut()))
                .chain(self.snapshot.stripe.iter_mut());
            for st in stripes {
                st.parity.retain(|(_, _, p)| p != node);
            }
            for u in self.users.values_mut() {
                u.retired.retain(|r| r.partner != node);
            }
            self.snapshot.retired.retain(|r| r.partner != node);
        }
        found
    }

    /// Vide la liste noire ; rend le nombre de Nœuds retirés.
    pub fn clear_blacklist(&mut self) -> usize {
        let all: Vec<String> = self.upkeep.blacklist.keys().cloned().collect();
        all.iter().filter(|n| self.unblacklist(n)).count()
    }

    /// Retire des listes d'orphelins les fragments encore attendus : un
    /// stripe redispersé à l'identique (nouvel essai après des confirmations
    /// insuffisantes) replace les mêmes fragments chez les mêmes partenaires,
    /// et l'avis d'effacement les détruirait.
    pub fn drop_referenced_retired(&mut self) {
        let live = self.referenced();
        let keep = |r: &Retired| !live.contains(&(r.hash.clone(), r.partner.clone()));
        for u in self.users.values_mut() {
            u.retired.retain(keep);
        }
        self.snapshot.retired.retain(keep);
    }
}

/// Bilan d'un cycle.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CycleReport {
    pub stripes_dispersed: usize,
    pub published: usize,
    pub purged: u64,
    pub errors: Vec<String>,
}

// ---------------------------------------------------------------- moteur

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("CSPRNG du système");
    b
}

/// Disperse un stripe de k blocs de 65 536 o.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn disperse(
    service: &Mutex<NodeService>,
    fabric: &dyn Fabric,
    cfg: &EngineConfig,
    data: &[Vec<u8>],
    padding: &[bool],
    salt: Option<[u8; 16]>,
    retired: &mut Vec<Retired>,
    now: u64,
) -> Result<StripeRec, String> {
    let hashes: Vec<Id> = data.iter().map(|d| hash_sha256(d)).collect();
    let sid = stripe_id(&hashes);
    let refs: Vec<&[u8]> = data.iter().map(|d| d.as_slice()).collect();
    let parity = encode_parity(&refs, cfg.coef).map_err(|e| e.to_string())?;
    let me = service.lock().unwrap().node_id();
    let mut candidates: Vec<Id> = fabric.partners().iter().map(|p| p.node_id).collect();
    by_xor_distance(&mut candidates, &sid);
    let mut next = 0;
    let mut placed: Vec<(u16, String, String)> = Vec::new();
    for (i, frag) in parity.into_iter().enumerate() {
        let h = hash_sha256(&frag);
        while next < candidates.len() {
            let p = candidates[next];
            next += 1;
            if let Ok(sig) = fabric.store(&p, frag.clone()).await {
                if verify_receipt(&p, &h, &me, &sig) {
                    if let Some(st) = service.lock().unwrap().partners.get_mut(&p) {
                        st.ledger.hosted_for_partner += 1;
                    }
                    placed.push(((cfg.k + i) as u16, hx(&h), hx(&p)));
                    break;
                }
            }
        }
    }
    // Partenaires manquants (`protocols.partenariat-automatique`) : la
    // recherche relève sa cible d'autant.
    service.lock().unwrap().missing_partners =
        cfg.k * cfg.coef - placed.len().min(cfg.k * cfg.coef);
    let rec = StripeRec {
        id: hx(&sid),
        data: hashes.iter().map(|h| hx(h)).collect(),
        padding: padding.to_vec(),
        parity: placed,
        salt: salt.map(|s| hx(&s)),
    };
    if rec.parity.len() < cfg.min_confirmations() {
        retire(&rec, retired, now);
        return Err(format!(
            "confirmations insuffisantes : {}/{} (partenaires joignables : {})",
            rec.parity.len(),
            cfg.min_confirmations(),
            candidates.len()
        ));
    }
    Ok(rec)
}

pub(crate) fn retire(rec: &StripeRec, retired: &mut Vec<Retired>, now: u64) {
    retired.extend(rec.parity.iter().map(|(_, h, p)| Retired {
        at: now,
        hash: h.clone(),
        partner: p.clone(),
    }));
}

/// Table `Partner` du manifeste : `node_id` → `partner_id` (1, 2, …).
#[derive(Default)]
pub(crate) struct PartnerTable {
    ids: HashMap<Id, u16>,
    pub(crate) list: Vec<PartnerDesc>,
}

impl PartnerTable {
    pub(crate) fn id_of(&mut self, node: &Id, reach: &[Reachable]) -> u16 {
        if let Some(i) = self.ids.get(node) {
            return *i;
        }
        let i = self.list.len() as u16 + 1;
        let r = reach.iter().find(|r| r.node_id == *node);
        self.list.push(PartnerDesc {
            partner_id: i,
            node_id: *node,
            ip: r.map(|r| r.ip.clone()).unwrap_or_default(),
            port: r.map(|r| r.port).unwrap_or(0),
        });
        self.ids.insert(*node, i);
        i
    }

    pub(crate) fn desc(&mut self, rec: &StripeRec, k: usize, reach: &[Reachable]) -> StripeDesc {
        let mut blocks: Vec<BlockRef> = rec
            .data
            .iter()
            .enumerate()
            .map(|(i, h)| BlockRef {
                hash: id(h),
                index: i as u16,
                partner_id: 0,
                key_version: 1,
                is_padding: rec.padding.get(i).copied().unwrap_or(false),
            })
            .collect();
        for (i, h, p) in &rec.parity {
            blocks.push(BlockRef {
                hash: id(h),
                index: *i,
                partner_id: self.id_of(&id(p), reach),
                key_version: 1,
                is_padding: false,
            });
        }
        StripeDesc {
            stripe_id: id(&rec.id),
            k: k as u8,
            m: (blocks.len()) as u8,
            blocks,
            encryption_salt: rec.salt.as_deref().map(|s| {
                hex::decode(s)
                    .ok()
                    .and_then(|v| v.try_into().ok())
                    .unwrap_or([0; 16])
            }),
        }
    }
}

/// Stripe d'index : bloc chiffré + k−1 blocs de padding.
fn index_blocks(frame: Vec<u8>, k: usize) -> (Vec<Vec<u8>>, Vec<bool>) {
    let mut data = vec![frame];
    let mut pad = vec![false];
    for _ in 1..k {
        data.push(padding_block());
        pad.push(true);
    }
    (data, pad)
}

/// Réémet l'arbre d'index et publie l'entrée DHT.
#[allow(clippy::too_many_arguments)]
async fn publish_tree(
    service: &Mutex<NodeService>,
    fabric: &dyn Fabric,
    cfg: &EngineConfig,
    user: &Id,
    k_attach: &[u8; 32],
    u: &mut UserDispersal,
    now: u64,
) -> Result<(), String> {
    let kdc = derive_k_dispersal_content(k_attach).map_err(|e| e.to_string())?;
    let reach = fabric.partners();
    let mut table = PartnerTable::default();
    let mut new_index: Vec<StripeRec> = Vec::new();
    let mut level: Vec<StripeDesc> = u
        .stripes
        .iter()
        .map(|s| table.desc(s, cfg.k, &reach))
        .collect();
    let mut is_leaf = true;
    let seal = |salt: &[u8; 16], bytes: &[u8]| {
        seal_index_node(&kdc, salt, &CURRENT_HEADER, &random::<12>(), bytes)
            .map_err(|e| e.to_string())
    };
    // Niveaux intermédiaires, de bas en haut, jusqu'à tenir dans la racine.
    while level.len() > INDEX_FANOUT {
        let mut parents = Vec::new();
        for chunk in level.chunks(INDEX_FANOUT) {
            let node = IndexNodeDesc {
                is_leaf,
                entries: chunk.to_vec(),
            };
            let salt = random::<16>();
            let (data, pad) = index_blocks(seal(&salt, &encode_index_node(&node))?, cfg.k);
            let rec = disperse(
                service,
                fabric,
                cfg,
                &data,
                &pad,
                Some(salt),
                &mut u.retired,
                now,
            )
            .await?;
            parents.push(table.desc(&rec, cfg.k, &reach));
            new_index.push(rec);
        }
        level = parents;
        is_leaf = false;
    }
    let node_id = service.lock().unwrap().node_id();
    let manifest = ManifestDesc {
        user_id: *user,
        node_id,
        partners: table.list.clone(),
        root: IndexNodeDesc {
            is_leaf,
            entries: level,
        },
        timestamp: now,
    };
    let salt = random::<16>();
    let frame = seal(&salt, &encode_manifest(&manifest))?;
    let root_hash = hash_sha256(&frame);
    let (data, pad) = index_blocks(frame, cfg.k);
    let root = disperse(
        service,
        fabric,
        cfg,
        &data,
        &pad,
        Some(salt),
        &mut u.retired,
        now,
    )
    .await?;
    let mut root_table = PartnerTable::default();
    let root_stripe = root_table.desc(&root, cfg.k, &reach);
    let pointer = RootPointer {
        root_hash,
        partners: root_table.list,
        salt,
        root_stripe,
    };
    new_index.push(root);
    publish(fabric, user, &node_id, k_attach, &pointer, u, now).await?;
    // Commit : les anciens stripes d'index deviennent orphelins.
    for old in std::mem::replace(&mut u.index, new_index) {
        retire(&old, &mut u.retired, now);
    }
    u.dirty = false;
    Ok(())
}

async fn publish(
    fabric: &dyn Fabric,
    user: &Id,
    node_id: &Id,
    k_attach: &[u8; 32],
    pointer: &RootPointer,
    u: &mut UserDispersal,
    now: u64,
) -> Result<(), String> {
    let env = dispersal_entry_envelope(k_attach, now, &random::<12>(), pointer)
        .map_err(|e| e.to_string())?;
    fabric
        .publish(dispersal_dht_key(k_attach).to_vec(), env)
        .await?;
    u.pointer = Some(hx(&encode_root_pointer(pointer)));
    u.published_at = now;
    u.next_republish = next_republish_at(&[&user[..], &node_id[..]].concat(), now + 1);
    Ok(())
}

/// Forme et disperse les stripes de données en attente.
async fn disperse_pending(
    service: &Mutex<NodeService>,
    fabric: &dyn Fabric,
    cfg: &EngineConfig,
    user: &Id,
    u: &mut UserDispersal,
    now: u64,
    report: &mut CycleReport,
) -> Result<(), String> {
    // Stripe partiel recréé dès l'arrivée de vrais blocs.
    if !u.pending.is_empty() && u.stripes.last().is_some_and(|s| s.padding.contains(&true)) {
        let old = u.stripes.pop().unwrap();
        let real: Vec<String> = old
            .data
            .iter()
            .zip(&old.padding)
            .filter(|(_, p)| !**p)
            .map(|(h, _)| h.clone())
            .collect();
        let mut pending = real;
        pending.append(&mut u.pending);
        u.pending = pending;
        retire(&old, &mut u.retired, now);
        u.dirty = true;
    }
    loop {
        let full = u.pending.len() >= cfg.k;
        let idle = !u.pending.is_empty() && now >= u.pending_since + cfg.idle_timeout_s;
        if !full && !idle {
            return Ok(());
        }
        let take = u.pending.len().min(cfg.k);
        let mut data = Vec::with_capacity(cfg.k);
        let mut pad = Vec::with_capacity(cfg.k);
        for h in &u.pending[..take] {
            let block = service
                .lock()
                .unwrap()
                .store
                .get(Space::UserBlock, &id(h))
                .filter(|(o, _)| o == user)
                .map(|(_, d)| d)
                .ok_or(format!("bloc {h} introuvable"))?;
            if block.len() != padding_block().len() {
                return Err(format!(
                    "bloc {h} : taille {} au lieu de 65 536",
                    block.len()
                ));
            }
            data.push(block);
            pad.push(false);
        }
        while data.len() < cfg.k {
            data.push(padding_block());
            pad.push(true);
        }
        let rec = disperse(service, fabric, cfg, &data, &pad, None, &mut u.retired, now).await?;
        u.pending.drain(..take);
        u.pending_since = now;
        u.stripes.push(rec);
        u.dirty = true;
        report.stripes_dispersed += 1;
    }
}

/// Purge les fragments orphelins dont le délai de grâce est échu.
async fn purge(
    service: &Mutex<NodeService>,
    fabric: &dyn Fabric,
    cfg: &EngineConfig,
    state: &mut DispersalState,
    now: u64,
) -> u64 {
    let priv_node = service.lock().unwrap().priv_node();
    state.drop_referenced_retired();
    let mut by_partner: BTreeMap<String, Vec<Id>> = BTreeMap::new();
    let lists = state
        .users
        .values()
        .map(|u| &u.retired)
        .chain(std::iter::once(&state.snapshot.retired));
    for list in lists {
        for r in list.iter().filter(|r| r.at + cfg.grace_s <= now) {
            by_partner
                .entry(r.partner.clone())
                .or_default()
                .push(id(&r.hash));
        }
    }
    let mut freed_total = 0;
    for (partner, hashes) in by_partner {
        let last = state.last_tombstone.get(&partner).copied().unwrap_or(0);
        let ts = now.max(last + 1);
        let notice = TombstoneNotice::sign(&priv_node, ts, hashes.clone());
        if let Ok(freed) = fabric.tombstone(&id(&partner), &notice).await {
            state.last_tombstone.insert(partner.clone(), ts);
            if let Some(st) = service.lock().unwrap().partners.get_mut(&id(&partner)) {
                apply_acknowledged(&mut st.ledger, freed);
            }
            freed_total += freed;
            let done: std::collections::HashSet<String> = hashes.iter().map(|h| hx(h)).collect();
            for u in state.users.values_mut() {
                u.retired
                    .retain(|r| !(r.partner == partner && done.contains(&r.hash)));
            }
            state
                .snapshot
                .retired
                .retain(|r| !(r.partner == partner && done.contains(&r.hash)));
        }
    }
    freed_total
}

/// Un cycle de dispersion pour tous les Utilisateurs rattachés.
pub async fn run_cycle(
    service: &Mutex<NodeService>,
    state: &mut DispersalState,
    fabric: &dyn Fabric,
    cfg: &EngineConfig,
    now: u64,
) -> CycleReport {
    let mut report = CycleReport::default();
    let (users, queue, priv_node) = {
        let mut s = service.lock().unwrap();
        let users: Vec<(Id, Vec<u8>)> = s.users.iter().map(|(i, a)| (*i, a.salt.clone())).collect();
        (users, std::mem::take(&mut s.dispersal_queue), s.priv_node())
    };
    for (user, hash) in queue {
        let known = state.known(&user);
        let u = state.users.entry(hx(&user)).or_default();
        if !known.contains(&hx(&hash)) {
            if u.pending.is_empty() {
                u.pending_since = now;
            }
            u.pending.push(hx(&hash));
        }
    }
    let node_id = service.lock().unwrap().node_id();
    for (user, salt) in users {
        let Ok(k_attach) = derive_k_attach_as_node(&priv_node, &user, &salt) else {
            continue;
        };
        let mut u = state.users.remove(&hx(&user)).unwrap_or_default();
        let mut result =
            disperse_pending(service, fabric, cfg, &user, &mut u, now, &mut report).await;
        if result.is_ok() && u.dirty && !u.stripes.is_empty() {
            result = publish_tree(service, fabric, cfg, &user, &k_attach, &mut u, now).await;
            if result.is_ok() {
                report.published += 1;
            }
        } else if result.is_ok() && !u.dirty && u.pointer.is_some() && now >= u.next_republish {
            let pointer = u
                .pointer
                .as_deref()
                .and_then(|p| hex::decode(p).ok())
                .and_then(|b| decode_root_pointer(&b).ok());
            if let Some(p) = pointer {
                result = publish(fabric, &user, &node_id, &k_attach, &p, &mut u, now).await;
                if result.is_ok() {
                    report.published += 1;
                }
            }
        }
        if let Err(e) = &result {
            report.errors.push(format!("{} : {e}", &hx(&user)[..16]));
        }
        u.last_error = result.err();
        state.users.insert(hx(&user), u);
    }
    report.purged = purge(service, fabric, cfg, state, now).await;
    report
}

/// Remet en attente les blocs d'Utilisateurs absents de l'état (reprise
/// après arrêt brutal entre réception et cycle).
pub fn reconcile(service: &Mutex<NodeService>, state: &mut DispersalState, now: u64) -> usize {
    let s = service.lock().unwrap();
    let mut added = 0;
    for user in s.users.keys() {
        let known = state.known(user);
        let u = state.users.entry(hx(user)).or_default();
        for h in s.store.hashes(Space::UserBlock, user) {
            if !known.contains(&hx(&h)) {
                if u.pending.is_empty() {
                    u.pending_since = now;
                }
                u.pending.push(hx(&h));
                added += 1;
            }
        }
    }
    added
}

// ------------------------------------------------------- réseau réel

/// `Fabric` sur le serveur d'échange de blocs et l'adaptateur DHT du Nœud.
pub struct NetFabric {
    pub server: std::sync::Arc<crate::exchange::BlockServer>,
    pub dht: std::sync::Arc<crate::dht_directory::DhtNode>,
    pub service: std::sync::Arc<Mutex<NodeService>>,
    /// Adresses `/ip4/…/tcp/…/p2p/<PeerId>` des partenaires.
    pub addrs: std::sync::Arc<Mutex<HashMap<Id, String>>>,
    /// Partenaires exclus des nouveaux placements (score bas, retrait).
    pub excluded: std::sync::Arc<Mutex<std::collections::HashSet<Id>>>,
}

impl NetFabric {
    fn addr(&self, partner: &Id) -> Result<libp2p::Multiaddr, String> {
        self.addrs
            .lock()
            .unwrap()
            .get(partner)
            .ok_or("adresse inconnue")?
            .parse()
            .map_err(|e: libp2p::multiaddr::Error| e.to_string())
    }
}

#[async_trait::async_trait]
impl Fabric for NetFabric {
    fn partners(&self) -> Vec<Reachable> {
        let excluded = self.excluded.lock().unwrap().clone();
        let known: Vec<Id> = self
            .service
            .lock()
            .unwrap()
            .partners
            .keys()
            .copied()
            .filter(|p| !excluded.contains(p))
            .collect();
        let addrs = self.addrs.lock().unwrap();
        known
            .into_iter()
            .filter_map(|id| {
                let a: libp2p::Multiaddr = addrs.get(&id)?.parse().ok()?;
                let mut ip = String::new();
                let mut port = 0;
                for p in a.iter() {
                    match p {
                        libp2p::multiaddr::Protocol::Ip4(v) => ip = v.to_string(),
                        libp2p::multiaddr::Protocol::Ip6(v) => ip = v.to_string(),
                        libp2p::multiaddr::Protocol::Tcp(v) => port = v,
                        _ => {}
                    }
                }
                Some(Reachable {
                    node_id: id,
                    ip,
                    port,
                })
            })
            .collect()
    }

    async fn store(&self, partner: &Id, data: Vec<u8>) -> Result<Vec<u8>, String> {
        let req = Request {
            credential: None,
            body: Body::StoreFragment { data },
        };
        match self.server.request(self.addr(partner)?, req).await {
            Ok(s3m_protocol::exchange::Response::FragmentReceipt { signature, .. }) => {
                Ok(signature)
            }
            Ok(r) => Err(format!("{r:?}")),
            Err(e) => Err(e.to_string()),
        }
    }

    async fn tombstone(&self, partner: &Id, notice: &TombstoneNotice) -> Result<u64, String> {
        match self
            .server
            .request(self.addr(partner)?, tombstone_request(notice))
            .await
        {
            Ok(s3m_protocol::exchange::Response::Ack { freed }) => Ok(freed),
            Ok(r) => Err(format!("{r:?}")),
            Err(e) => Err(e.to_string()),
        }
    }

    async fn publish(&self, key: Vec<u8>, envelope: Vec<u8>) -> Result<(), String> {
        self.dht.put(key, envelope).await.map_err(|e| e.to_string())
    }

    async fn request(
        &self,
        partner: &Id,
        req: Request,
    ) -> Result<s3m_protocol::exchange::Response, String> {
        self.server
            .request(self.addr(partner)?, req)
            .await
            .map_err(|e| e.to_string())
    }
}
