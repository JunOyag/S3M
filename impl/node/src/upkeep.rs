//! Contrôles et réparation automatiques — ids `securite.pos-challenges`,
//! `securite.blacklist-fraude`, `protocols.volatilite-reparation`,
//! `securite.integrite-autoreparation` (orchestration par l'exécutable du
//! Nœud). Réf. spec : pages correspondantes.
//!
//! À chaque cycle :
//! 1. **Challenges PoS** sur un lot de fragments de parité des stripes de
//!    données, à tour de rôle : référence recalculée en local
//!    (Reed-Solomon sur les k blocs locaux), délai selon la latence mesurée.
//!    Réponse fausse ou fragment absent = fraude ; pas de réponse = absence.
//! 2. **Fraude** : rupture immédiate — liste noire permanente, destruction
//!    de ce qu'on hébergeait pour P, solde remis à zéro, P retiré des
//!    partenaires, réparation immédiate de tous les fragments confiés à P.
//! 3. **Analyse de volatilité** (période configurable, quotidienne par
//!    défaut) : un stripe dont moins de k+2 fragments sont disponibles voit
//!    ses fragments indisponibles régénérés et replacés chez de nouveaux
//!    partenaires distincts ; l'ancien fragment est purgé par tombstone
//!    quand son hébergeur redevient joignable. Les stripes d'index ne sont
//!    pas challengés (pas de copie locale) : l'arbre est réémis si l'un
//!    d'eux tombe sous k+2.
//! 4. **Scrubbing** de la copie locale : un bloc absent ou altéré est
//!    reconstruit depuis la parité des partenaires puis réécrit.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use s3m_core::erasure::{encode_parity, padding_block, reconstruct_data};
use s3m_core::symmetric_suite::hash_sha256;
use s3m_protocol::dispersal::{by_xor_distance, Id};
use s3m_protocol::exchange::{verify_receipt, Body, Refusal, Request, Response};
use serde::{Deserialize, Serialize};

use crate::blacklist::REASON_POS_INVALID;
use crate::chunk_store::Space;
use crate::dispersal_engine::{place, DispersalState, EngineConfig, Fabric, Retired, StripeRec};
use crate::exchange::{NodeService, PartnerState};
use crate::tombstones::{apply_acknowledged, TombstoneNotice};
use crate::pos::{challenge_response, judge, LatencyTracker, Verdict};
use crate::volatility::{analyze, Holder};

/// Paramètres des contrôles.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct UpkeepConfig {
    /// Challenges envoyés par cycle (tour de rôle sur tous les fragments).
    pub challenges_per_cycle: usize,
    /// Période de l'analyse de volatilité.
    pub analysis_period_s: u64,
    /// Un partenaire est disponible s'il a réussi un challenge depuis
    /// moins de cette durée.
    pub available_window_s: u64,
    /// Période du scrubbing de la copie locale.
    pub scrub_period_s: u64,
}

impl Default for UpkeepConfig {
    fn default() -> Self {
        Self {
            challenges_per_cycle: 16,
            analysis_period_s: 86_400,
            available_window_s: 86_400,
            scrub_period_s: 86_400,
        }
    }
}

/// État des contrôles (persisté avec l'état de dispersion).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpkeepState {
    /// Dernier challenge réussi, par partenaire.
    pub last_seen: BTreeMap<String, u64>,
    /// Latence moyenne mesurée (ms), par partenaire.
    pub latency_ms: BTreeMap<String, u64>,
    /// Liste noire locale permanente : `node_id → (date, motif)`.
    pub blacklist: BTreeMap<String, (u64, String)>,
    pub cursor: usize,
    pub last_analysis: u64,
    pub last_scrub: u64,
    /// Derniers événements (dashboard), plus récent en dernier.
    pub events: Vec<String>,
    pub challenges_passed: u64,
    pub challenges_timeout: u64,
    /// Challenges réussis / sans réponse, par partenaire (score de fiabilité).
    #[serde(default)]
    pub pos_ok: BTreeMap<String, u64>,
    #[serde(default)]
    pub pos_fail: BTreeMap<String, u64>,
    /// Partenaires en retrait (`partnering`) : fragments à replacer.
    #[serde(default)]
    pub retiring: BTreeSet<String>,
    /// Fragments de remplissage confiés : `partenaire → [(indice, hash)]`
    /// (`node.PartnerAccount#remplissage`).
    #[serde(default)]
    pub fillers: BTreeMap<String, Vec<(u64, String)>>,
    #[serde(default)]
    pub filler_next: u64,
    #[serde(default)]
    pub filler_cursor: usize,
    /// Maintenance en cours après la perte d'un volume.
    #[serde(default)]
    pub maintenance: Option<Maintenance>,
    /// Dernière maintenance terminée (dashboard).
    #[serde(default)]
    pub last_maintenance: Option<Maintenance>,
}

/// Maintenance après la perte de fichiers de conteneurs
/// (`securite.integrite-autoreparation#maintenance`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Maintenance {
    pub since: u64,
    pub lost_user_blocks: usize,
    pub lost_fragments: usize,
    pub lost_emergency: usize,
    pub repaired: usize,
    pub irrecoverable: usize,
    pub passes: u32,
    #[serde(default)]
    pub ended_at: Option<u64>,
    /// Cause : fichiers disparus (vide) ou altération massive.
    #[serde(default)]
    pub reason: String,
}

/// Altérations dans [`MASS_WINDOW_S`] qui déclenchent la maintenance.
pub const MASS_CORRUPTIONS: usize = 3;
pub const MASS_WINDOW_S: u64 = 600;
pub const REASON_MASS: &str = "altération massive";

/// Série d'altérations récentes : maintenance et relecture complète
/// (`securite.integrite-autoreparation#alteration-massive`).
fn detect_mass_corruption(service: &Mutex<NodeService>, up: &mut UpkeepState, now: u64) {
    let mut s = service.lock().unwrap();
    s.corruption_events
        .retain(|t| t.saturating_add(MASS_WINDOW_S) > now);
    if s.corruption_events.len() < MASS_CORRUPTIONS || up.maintenance.is_some() {
        return;
    }
    let n = s.corruption_events.len();
    s.corruption_events.clear();
    s.maintenance = true;
    let priv_node = s.priv_node();
    let _ = s.channel.post_info(
        &priv_node,
        "Maintenance : des données altérées ont été détectées sur le stockage de votre Nœud. Il vérifie et reconstruit vos fichiers depuis le réseau ; ils restent lisibles pendant ce temps.",
        now,
    );
    drop(s);
    up.maintenance = Some(Maintenance {
        since: now,
        reason: REASON_MASS.into(),
        ..Default::default()
    });
    up.last_scrub = 0;
    up.log(
        now,
        format!("{n} blocs altérés en moins de {} min : maintenance, relecture complète et reconstruction", MASS_WINDOW_S / 60),
    );
}

/// Passages de reconstruction au plus avant de sortir de maintenance.
pub const MAINTENANCE_PASSES: u32 = 10;

/// Fragments de remplissage déposés ou libérés par partenaire et par cycle.
pub const FILLER_BATCH: usize = 16;

/// Fragment de remplissage `index` : 64 Kio pseudo-aléatoires sous une clé
/// dérivée de `priv_node`, régénérables par ce Nœud seul.
pub fn filler_data(priv_node: &[u8; 32], index: u64) -> Vec<u8> {
    let key = hash_sha256(&[&priv_node[..], b"s3m-filler-v1"].concat());
    let mut out = Vec::with_capacity(65_536);
    let mut buf = [0u8; 48];
    buf[..32].copy_from_slice(&key);
    buf[32..40].copy_from_slice(&index.to_be_bytes());
    for j in 0..2048u64 {
        buf[40..].copy_from_slice(&j.to_be_bytes());
        out.extend_from_slice(&hash_sha256(&buf));
    }
    out
}

const MAX_EVENTS: usize = 50;

impl UpkeepState {
    fn log(&mut self, now: u64, msg: String) {
        self.events.push(format!("{now} {msg}"));
        let n = self.events.len();
        if n > MAX_EVENTS {
            self.events.drain(..n - MAX_EVENTS);
        }
    }

    pub fn is_blacklisted(&self, node_id: &Id) -> bool {
        self.blacklist.contains_key(&hex::encode(node_id))
    }
}

/// Bilan d'un cycle de contrôle.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpkeepReport {
    pub challenged: usize,
    pub passed: usize,
    pub timeouts: usize,
    pub frauds: Vec<Id>,
    /// Fragments introuvables chez leur partenaire : perdus, replacés.
    pub lost: usize,
    pub repaired: usize,
    pub local_repaired: usize,
}

fn hx(b: &[u8]) -> String {
    hex::encode(b)
}

fn id(s: &str) -> Id {
    hex::decode(s)
        .ok()
        .and_then(|v| v.try_into().ok())
        .unwrap_or([0; 32])
}

fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("CSPRNG du système");
    b
}

/// k blocs de données locaux d'un stripe (padding = zéros).
fn local_data(service: &Mutex<NodeService>, user: &Id, rec: &StripeRec) -> Option<Vec<Vec<u8>>> {
    let s = service.lock().unwrap();
    rec.data
        .iter()
        .zip(&rec.padding)
        .map(|(h, pad)| {
            if *pad {
                return Some(padding_block());
            }
            s.store
                .get(Space::UserBlock, &id(h))
                .filter(|(o, d)| o == user && hash_sha256(d) == id(h))
                .map(|(_, d)| d)
        })
        .collect()
}

fn parity_of(data: &[Vec<u8>], coef: usize) -> Option<Vec<Vec<u8>>> {
    let refs: Vec<&[u8]> = data.iter().map(|d| d.as_slice()).collect();
    encode_parity(&refs, coef).ok()
}

/// Replace les fragments `indices` d'un stripe chez de nouveaux partenaires.
#[allow(clippy::too_many_arguments)]
async fn replace_fragments(
    service: &Mutex<NodeService>,
    fabric: &dyn Fabric,
    cfg: &EngineConfig,
    up: &UpkeepState,
    rec: &mut StripeRec,
    parity: &[Vec<u8>],
    indices: &[u16],
    retired: &mut Vec<Retired>,
    now: u64,
) -> usize {
    let taken: HashSet<String> = rec.parity.iter().map(|(_, _, p)| p.clone()).collect();
    let mut candidates: Vec<Id> = fabric
        .partners()
        .iter()
        .map(|p| p.node_id)
        .filter(|p| !taken.contains(&hx(p)) && !up.is_blacklisted(p))
        .collect();
    by_xor_distance(&mut candidates, &id(&rec.id));
    let frags = indices
        .iter()
        .filter_map(|&i| Some((i, parity.get((i as usize).checked_sub(cfg.k)?)?.clone())))
        .collect();
    let placed = place(service, fabric, frags, &candidates, now).await;
    for (i, h, p) in &placed {
        if let Some(slot) = rec.parity.iter_mut().find(|(x, _, _)| x == i) {
            retired.push(Retired {
                at: now,
                hash: slot.1.clone(),
                partner: slot.2.clone(),
            });
            *slot = (*i, hx(h), hx(p));
        } else {
            rec.parity.push((*i, hx(h), hx(p)));
        }
    }
    rec.parity.sort();
    placed.len()
}

/// Remplissage de l'espace promis (`node.PartnerAccount#remplissage`) :
/// libère du remplissage chez les partenaires qui manquent de place pour
/// un vrai fragment, en dépose chez ceux qui gardent moins que le quota,
/// et en contrôle quelques-uns.
#[allow(clippy::too_many_arguments)]
async fn fillers(
    service: &Mutex<NodeService>,
    fabric: &dyn Fabric,
    up: &mut UpkeepState,
    last_tombstone: &mut BTreeMap<String, u64>,
    frauds: &mut BTreeSet<Id>,
    ucfg: &UpkeepConfig,
    report: &mut UpkeepReport,
    now: u64,
) {
    let (priv_node, me, pol, need, partners, suspended) = {
        let mut s = service.lock().unwrap();
        let need: Vec<Id> = s.need_room.drain().collect();
        let partners: Vec<(Id, PartnerState)> = s.partners.iter().map(|(i, p)| (*i, *p)).collect();
        (s.priv_node(), s.node_id(), s.partner_policy, need, partners, s.suspended(now))
    };
    // Partenariats terminés : leur remplissage est oublié.
    up.fillers
        .retain(|k, _| partners.iter().any(|(p, _)| hx(p) == *k));
    // Libération : place pour de vrais fragments (pas de nouveau
    // remplissage chez eux ce cycle-ci).
    for p in &need {
        let p = *p;
        let key = hx(&p);
        let Some(list) = up.fillers.get_mut(&key) else {
            continue;
        };
        let n = list.len().min(FILLER_BATCH);
        if n == 0 {
            continue;
        }
        let batch: Vec<(u64, String)> = list.split_off(list.len() - n);
        let last = last_tombstone.get(&key).copied().unwrap_or(0);
        let ts = now.max(last + 1);
        let notice = TombstoneNotice::sign(&priv_node, ts, batch.iter().map(|(_, h)| id(h)).collect());
        match fabric.tombstone(&p, &notice).await {
            Ok(freed) => {
                last_tombstone.insert(key, ts);
                if let Some(st) = service.lock().unwrap().partners.get_mut(&p) {
                    apply_acknowledged(&mut st.ledger, freed);
                }
            }
            Err(_) => up.fillers.get_mut(&key).unwrap().extend(batch),
        }
    }
    // Dépôt.
    if pol.filler {
        for (p, st) in &partners {
            let key = hx(p);
            if up.is_blacklisted(p)
                || up.retiring.contains(&key)
                || suspended.contains(p)
                || need.contains(p)
            {
                continue;
            }
            let room = pol.limit(st).saturating_sub(st.ledger.hosted_for_partner);
            for _ in 0..room.min(FILLER_BATCH as u64) {
                let index = up.filler_next;
                let data = filler_data(&priv_node, index);
                let h = hash_sha256(&data);
                match fabric.store(p, data).await {
                    Ok(sig) if verify_receipt(p, &h, &me, &sig) => {
                        up.filler_next += 1;
                        if let Some(s) = service.lock().unwrap().partners.get_mut(p) {
                            s.ledger.hosted_for_partner += 1;
                        }
                        up.fillers.entry(key.clone()).or_default().push((index, hx(&h)));
                    }
                    Err(e) => {
                        if e.contains("QuotaExceeded") {
                            crate::dispersal_engine::refused(service, p, now);
                        }
                        break;
                    }
                    _ => break,
                }
            }
        }
    }
    // Contrôle, à tour de rôle.
    let all: Vec<(String, u64, String)> = up
        .fillers
        .iter()
        .flat_map(|(p, v)| v.iter().map(move |(i, h)| (p.clone(), *i, h.clone())))
        .collect();
    if all.is_empty() {
        return;
    }
    let n = (ucfg.challenges_per_cycle / 4).max(1).min(all.len());
    for j in 0..n {
        let (partner, index, hash) = &all[(up.filler_cursor + j) % all.len()];
        let pid = id(partner);
        if frauds.contains(&pid) || up.is_blacklisted(&pid) {
            continue;
        }
        let data = filler_data(&priv_node, *index);
        let nonce = random32();
        let expected = challenge_response(&data, &nonce);
        let req = Request {
            credential: None,
            body: Body::Challenge {
                hash: id(hash).to_vec(),
                nonce: nonce.to_vec(),
            },
        };
        let answer = tokio::time::timeout(Duration::from_secs(10), fabric.request(&pid, req)).await;
        report.challenged += 1;
        match answer {
            Ok(Ok(Response::Failure(r @ (Refusal::NotFound | Refusal::Maintenance)))) => {
                if r == Refusal::NotFound {
                    *up.pos_fail.entry(partner.clone()).or_default() += 1;
                    service.lock().unwrap().record_failure(&pid, now);
                }
                if let Some(v) = up.fillers.get_mut(partner) {
                    v.retain(|(i, _)| i != index);
                }
                if let Some(st) = service.lock().unwrap().partners.get_mut(&pid) {
                    st.ledger.hosted_for_partner = st.ledger.hosted_for_partner.saturating_sub(1);
                }
                report.lost += 1;
            }
            Ok(Ok(Response::ChallengeResponse(d))) => {
                let d: Option<[u8; 32]> = d.try_into().ok();
                match judge(&expected, d.as_ref()) {
                    Verdict::Passed => {
                        up.last_seen.insert(partner.clone(), now);
                        *up.pos_ok.entry(partner.clone()).or_default() += 1;
                        if let Some(st) = service.lock().unwrap().partners.get_mut(&pid) {
                            st.proved_at = now;
                        }
                        report.passed += 1;
                    }
                    Verdict::Fraud => {
                        frauds.insert(pid);
                    }
                    Verdict::Timeout => {
                        *up.pos_fail.entry(partner.clone()).or_default() += 1;
                        report.timeouts += 1;
                    }
                }
            }
            _ => {
                *up.pos_fail.entry(partner.clone()).or_default() += 1;
                report.timeouts += 1;
            }
        }
    }
    up.filler_cursor = (up.filler_cursor + n) % all.len();
}

/// Rupture avec un partenaire fraudeur.
fn rupture(service: &Mutex<NodeService>, up: &mut UpkeepState, partner: &Id, now: u64) {
    let mut s = service.lock().unwrap();
    s.store.remove_owner(Space::Fragment, partner);
    s.partners.remove(partner);
    up.blacklist
        .entry(hx(partner))
        .or_insert((now, REASON_POS_INVALID.to_string()));
    up.last_seen.remove(&hx(partner));
    up.log(
        now,
        format!("fraude : {} en liste noire", &hx(partner)[..16]),
    );
}

/// Un cycle de contrôle et de réparation.
pub async fn run_upkeep(
    service: &Mutex<NodeService>,
    state: &mut DispersalState,
    fabric: &dyn Fabric,
    cfg: &EngineConfig,
    ucfg: &UpkeepConfig,
    now: u64,
) -> UpkeepReport {
    let mut report = UpkeepReport::default();
    let mut up = std::mem::take(&mut state.upkeep);
    detect_loss(service, &mut up, now);
    detect_mass_corruption(service, &mut up, now);
    service.lock().unwrap().maintenance = up.maintenance.is_some();

    // 1. Challenges, à tour de rôle sur tous les fragments de données.
    let targets: Vec<(String, usize, u16, String, String)> = state
        .users
        .iter()
        .flat_map(|(u, d)| {
            d.stripes.iter().enumerate().flat_map(move |(si, s)| {
                s.parity
                    .iter()
                    .map(move |(i, h, p)| (u.clone(), si, *i, h.clone(), p.clone()))
            })
        })
        .collect();
    let mut frauds: BTreeSet<Id> = BTreeSet::new();
    // Fragments introuvables : `(utilisateur, stripe, indice)`.
    let mut lost: HashSet<(String, usize, u16)> = HashSet::new();
    if !targets.is_empty() {
        let n = ucfg.challenges_per_cycle.min(targets.len());
        for j in 0..n {
            let (user, si, index, hash, partner) = &targets[(up.cursor + j) % targets.len()];
            let pid = id(partner);
            if frauds.contains(&pid) || up.is_blacklisted(&pid) {
                continue;
            }
            let rec = &state.users[user].stripes[*si];
            let Some(parity) =
                local_data(service, &id(user), rec).and_then(|d| parity_of(&d, cfg.coef))
            else {
                continue;
            };
            let frag = &parity[*index as usize - cfg.k];
            if hx(&hash_sha256(frag)) != *hash {
                continue;
            }
            let nonce = random32();
            let expected = challenge_response(frag, &nonce);
            let mut lat = LatencyTracker::default();
            if let Some(m) = up.latency_ms.get(partner) {
                lat.record(*m);
            }
            let req = Request {
                credential: None,
                body: Body::Challenge {
                    hash: id(hash).to_vec(),
                    nonce: nonce.to_vec(),
                },
            };
            let t0 = Instant::now();
            let answer = tokio::time::timeout(
                Duration::from_millis(lat.timeout_ms()),
                fabric.request(&pid, req),
            )
            .await;
            report.challenged += 1;
            // Introuvable : perte, pas fraude (`securite.blacklist-fraude`
            // § Fragment introuvable) — échec compté, fragment replacé.
            // En maintenance : perte déclarée, sans manquement.
            if matches!(answer, Ok(Ok(Response::Failure(Refusal::Maintenance)))) {
                lost.insert((user.clone(), *si, *index));
                report.lost += 1;
                up.log(
                    now,
                    format!(
                        "fragment perdu chez {}… (en maintenance) : replacé",
                        &partner[..16.min(partner.len())]
                    ),
                );
                continue;
            }
            if matches!(answer, Ok(Ok(Response::Failure(Refusal::NotFound)))) {
                *up.pos_fail.entry(partner.clone()).or_default() += 1;
                service.lock().unwrap().record_failure(&pid, now);
                lost.insert((user.clone(), *si, *index));
                report.lost += 1;
                up.log(
                    now,
                    format!(
                        "fragment perdu chez {}… (stripe {}…) : replacé",
                        &partner[..16.min(partner.len())],
                        &state.users[user].stripes[*si].id[..12]
                    ),
                );
                continue;
            }
            let verdict = match answer {
                Ok(Ok(Response::ChallengeResponse(d))) => {
                    let d: Option<[u8; 32]> = d.try_into().ok();
                    match d {
                        Some(d) => judge(&expected, Some(&d)),
                        None => Verdict::Fraud,
                    }
                }
                _ => Verdict::Timeout,
            };
            match verdict {
                Verdict::Passed => {
                    let ms = t0.elapsed().as_millis() as u64;
                    lat.record(ms);
                    up.latency_ms
                        .insert(partner.clone(), lat.mean_ms().unwrap_or(ms));
                    up.last_seen.insert(partner.clone(), now);
                    *up.pos_ok.entry(partner.clone()).or_default() += 1;
                    if let Some(st) = service.lock().unwrap().partners.get_mut(&pid) {
                        st.proved_at = now;
                    }
                    up.challenges_passed += 1;
                    report.passed += 1;
                }
                Verdict::Timeout => {
                    *up.pos_fail.entry(partner.clone()).or_default() += 1;
                    up.challenges_timeout += 1;
                    report.timeouts += 1;
                }
                Verdict::Fraud => {
                    frauds.insert(pid);
                }
            }
        }
        up.cursor = (up.cursor + n) % targets.len();
    }

    // 1 bis. Remplissage : libération, dépôt, contrôle.
    fillers(service, fabric, &mut up, &mut state.last_tombstone, &mut frauds, ucfg, &mut report, now).await;

    // 2. Fraude : rupture et réparation immédiate.
    for p in &frauds {
        rupture(service, &mut up, p, now);
        report.frauds.push(*p);
    }
    let analysis_due = now >= up.last_analysis + ucfg.analysis_period_s;
    if analysis_due {
        up.last_analysis = now;
    }
    // Rattrapage : partenaires qui ne portent encore rien d'un stripe
    // incomplet ; arrêté au premier stripe qui ne progresse pas (partenaires
    // pleins), repris au cycle suivant.
    let partners: Vec<String> = fabric
        .partners()
        .iter()
        .map(|p| hx(&p.node_id))
        .filter(|p| !up.blacklist.contains_key(p) && !up.retiring.contains(p))
        .collect();
    let mut catch_up = true;
    let users: Vec<String> = state.users.keys().cloned().collect();
    for user in &users {
        let uid = id(user);
        let mut d = state.users.remove(user).unwrap();
        let mut changed = false;
        for si in 0..d.stripes.len() {
            let available = |p: &String| {
                !up.blacklist.contains_key(p)
                    && !up.retiring.contains(p)
                    && up
                        .last_seen
                        .get(p)
                        .is_some_and(|t| now.saturating_sub(*t) <= ucfg.available_window_s)
            };
            let rec = &d.stripes[si];
            let mut indices: Vec<u16> = rec
                .parity
                .iter()
                .filter(|(i, _, p)| {
                    frauds.contains(&id(p))
                        || up.retiring.contains(p)
                        || lost.contains(&(user.clone(), si, *i))
                })
                .map(|(i, _, _)| *i)
                .collect();
            // 3. Volatilité : réparation dès que moins de k+2 sont disponibles.
            if analysis_due {
                let holders: Vec<Holder> = rec
                    .parity
                    .iter()
                    .map(|(i, _, p)| Holder {
                        index: *i as usize,
                        partner: *i,
                        last_seen: if available(p) { now } else { 0 },
                    })
                    .collect();
                let plan = analyze(&holders, cfg.k, now, ucfg.available_window_s);
                indices.extend(plan.repair.iter().map(|i| *i as u16));
                // Fragments jamais placés (dispersion partielle).
            }
            // Fragments jamais placés (dispersion partielle) : à chaque cycle,
            // dès qu'un partenaire libre existe.
            let unplaced: Vec<u16> = {
                let placed: HashSet<u16> = rec.parity.iter().map(|(i, _, _)| *i).collect();
                (cfg.k..cfg.k * (1 + cfg.coef))
                    .map(|i| i as u16)
                    .filter(|i| !placed.contains(i))
                    .collect()
            };
            let catching_up = indices.is_empty() && !unplaced.is_empty();
            if !unplaced.is_empty()
                && (analysis_due || catch_up)
                && partners
                    .iter()
                    .any(|p| !rec.parity.iter().any(|(_, _, x)| x == p))
            {
                indices.extend(unplaced);
            } else if catching_up {
                continue;
            }
            indices.sort();
            indices.dedup();
            if indices.is_empty() {
                continue;
            }
            let Some(parity) =
                local_data(service, &uid, &d.stripes[si]).and_then(|x| parity_of(&x, cfg.coef))
            else {
                up.log(
                    now,
                    format!(
                        "réparation impossible : copie locale du stripe {}… illisible",
                        &d.stripes[si].id[..12]
                    ),
                );
                continue;
            };
            let mut rec = d.stripes[si].clone();
            let n = replace_fragments(
                service,
                fabric,
                cfg,
                &up,
                &mut rec,
                &parity,
                &indices,
                &mut d.retired,
                now,
            )
            .await;
            if n > 0 {
                report.repaired += n;
                changed = true;
                up.log(
                    now,
                    format!(
                        "réparation : {n}/{} fragment(s) replacé(s), stripe {}…",
                        indices.len(),
                        &rec.id[..12]
                    ),
                );
            }
            if catching_up && n == 0 {
                catch_up = false;
            }
            if n < indices.len() && (!catching_up || analysis_due) {
                up.log(
                    now,
                    format!(
                        "réparation incomplète, stripe {}… : partenaires insuffisants",
                        &rec.id[..12]
                    ),
                );
            }
            d.stripes[si] = rec;
        }
        // Stripes d'index : réémission de l'arbre si l'un d'eux faiblit.
        if analysis_due || !frauds.is_empty() {
            let weak = d.index.iter().any(|s| {
                s.parity
                    .iter()
                    .filter(|(_, _, p)| {
                        !frauds.contains(&id(p))
                            && !up.blacklist.contains_key(p)
                            && (!analysis_due
                                || up.last_seen.get(p).is_some_and(|t| {
                                    now.saturating_sub(*t) <= ucfg.available_window_s
                                }))
                    })
                    .count()
                    < cfg.min_confirmations()
            });
            if weak {
                changed = true;
            }
        }
        if changed {
            d.dirty = true;
        }
        state.users.insert(user.clone(), d);
    }

    // 4. Scrubbing de la copie locale.
    if now >= up.last_scrub + ucfg.scrub_period_s || up.maintenance.is_some() {
        up.last_scrub = now;
        let mut failed = 0usize;
        for user in &users {
            let uid = id(user);
            let stripes = state.users[user].stripes.clone();
            for rec in &stripes {
                for (pos, h) in rec.data.iter().enumerate() {
                    if rec.padding[pos] {
                        continue;
                    }
                    let ok = {
                        let mut s = service.lock().unwrap();
                        let got = s.store.get(Space::UserBlock, &id(h));
                        // Contenu relu différent : altération du disque.
                        if got.as_ref().is_some_and(|(o, b)| *o == uid && hx(&hash_sha256(b)) != *h) {
                            s.corruption_events.push(now);
                            if let Some(p) = s.store.physical() {
                                p.note_corrupted(&id(h));
                            }
                        }
                        got.is_some_and(|(o, b)| o == uid && hx(&hash_sha256(&b)) == *h)
                    };
                    if ok {
                        continue;
                    }
                    if heal_local(service, fabric, cfg, &uid, rec, pos).await {
                        report.local_repaired += 1;
                        up.log(
                            now,
                            format!("bloc local {}… reconstruit depuis la parité", &h[..12]),
                        );
                    } else {
                        failed += 1;
                        up.log(
                            now,
                            format!("bloc local {}… altéré, reconstruction impossible", &h[..12]),
                        );
                    }
                }
            }
        }
        end_pass(service, &mut up, report.local_repaired, failed, now);
    }
    state.upkeep = up;
    report
}

/// Fichiers de conteneurs disparus : conteneurs oubliés, soldes des
/// partenaires corrigés, passage en maintenance et message aux Utilisateurs.
fn detect_loss(service: &Mutex<NodeService>, up: &mut UpkeepState, now: u64) {
    let mut s = service.lock().unwrap();
    let Some(phys) = s.store.physical() else {
        return;
    };
    phys.check_volumes();
    let missing = phys.missing_containers();
    if missing.is_empty() {
        return;
    }
    let lost = match phys.forget_containers(&missing) {
        Ok(l) => l,
        Err(e) => {
            drop(s);
            up.log(now, format!("conteneurs disparus, oubli impossible : {e}"));
            return;
        }
    };
    let (mut users, mut frags, mut emergency) = (0, 0, 0);
    for (owner, hashes) in &lost {
        match owner.owner_type {
            crate::OwnerType::AttachedUser => users += hashes.len(),
            crate::OwnerType::Partner => {
                frags += hashes.len();
                if let Some(st) = <[u8; 32]>::try_from(owner.owner_id.as_slice())
                    .ok()
                    .and_then(|p| s.partners.get_mut(&p))
                {
                    st.ledger.hosted_by_partner =
                        st.ledger.hosted_by_partner.saturating_sub(hashes.len() as u64);
                }
            }
            crate::OwnerType::EmergencyDepositor => emergency += hashes.len(),
        }
    }
    let fresh = up.maintenance.is_none();
    let m = up.maintenance.get_or_insert(Maintenance {
        since: now,
        ..Default::default()
    });
    m.lost_user_blocks += users;
    m.lost_fragments += frags;
    m.lost_emergency += emergency;
    m.passes = 0;
    up.last_scrub = 0;
    s.maintenance = true;
    if fresh && users > 0 {
        let priv_node = s.priv_node();
        let _ = s.channel.post_info(
            &priv_node,
            "Maintenance : une partie du stockage de votre Nœud a été perdue. Il reconstruit vos fichiers depuis le réseau ; ils restent lisibles pendant ce temps.",
            now,
        );
    }
    drop(s);
    up.log(
        now,
        format!(
            "{} conteneur(s) disparu(s) du disque ({users} blocs d'Utilisateurs, {frags} fragments de partenaires, {emergency} dépôts d'urgence) : maintenance, reconstruction depuis le réseau",
            missing.len()
        ),
    );
}

/// Fin d'un passage de reconstruction : sortie de maintenance quand tout
/// est reconstruit, ou après `MAINTENANCE_PASSES` passages.
fn end_pass(
    service: &Mutex<NodeService>,
    up: &mut UpkeepState,
    repaired: usize,
    failed: usize,
    now: u64,
) {
    let Some(m) = up.maintenance.as_mut() else {
        return;
    };
    m.passes += 1;
    m.repaired += repaired;
    if failed > 0 && m.passes < MAINTENANCE_PASSES {
        return;
    }
    let mut m = up.maintenance.take().unwrap();
    m.irrecoverable = if m.reason == REASON_MASS {
        failed
    } else {
        m.lost_user_blocks.saturating_sub(m.repaired)
    };
    m.ended_at = Some(now);
    let text = if m.irrecoverable == 0 {
        format!("maintenance terminée : {} bloc(s) reconstruit(s)", m.repaired)
    } else {
        format!(
            "maintenance terminée : {} bloc(s) reconstruit(s), {} irrécupérable(s)",
            m.repaired, m.irrecoverable
        )
    };
    {
        let mut s = service.lock().unwrap();
        s.maintenance = false;
        if m.lost_user_blocks > 0 || (m.reason == REASON_MASS && m.repaired > 0) {
            let priv_node = s.priv_node();
            let msg = if m.irrecoverable == 0 {
                "Maintenance terminée : tous vos fichiers ont été reconstruits.".to_string()
            } else {
                format!("Maintenance terminée : {} bloc(s) n'ont pas pu être reconstruits ; un fichier illisible devra être renvoyé depuis un appareil qui en a encore une copie.", m.irrecoverable)
            };
            let _ = s.channel.post_info(&priv_node, &msg, now);
        }
    }
    up.log(now, text);
    up.last_maintenance = Some(m);
}

/// Reconstruit le bloc de données `pos` d'un stripe depuis la parité et le
/// réécrit localement.
async fn heal_local(
    service: &Mutex<NodeService>,
    fabric: &dyn Fabric,
    cfg: &EngineConfig,
    user: &Id,
    rec: &StripeRec,
    pos: usize,
) -> bool {
    let n = cfg.k * (1 + cfg.coef);
    let mut shards: Vec<Option<Vec<u8>>> = vec![None; n];
    let mut have = 0;
    {
        let s = service.lock().unwrap();
        for (i, (h, pad)) in rec.data.iter().zip(&rec.padding).enumerate() {
            if *pad {
                shards[i] = Some(padding_block());
                have += 1;
            } else if i != pos {
                if let Some((_, b)) = s
                    .store
                    .get(Space::UserBlock, &id(h))
                    .filter(|(o, b)| o == user && hx(&hash_sha256(b)) == *h)
                {
                    shards[i] = Some(b);
                    have += 1;
                }
            }
        }
    }
    for (i, h, p) in &rec.parity {
        if have >= cfg.k {
            break;
        }
        let req = Request {
            credential: None,
            body: Body::FetchFragment {
                hash: id(h).to_vec(),
            },
        };
        if let Ok(Response::BlockData(b)) = fabric.request(&id(p), req).await {
            if hx(&hash_sha256(&b)) == *h {
                shards[*i as usize] = Some(b);
                have += 1;
            }
        }
    }
    let Ok(data) = reconstruct_data(shards, cfg.k, cfg.coef) else {
        return false;
    };
    let block = &data[pos];
    let h = id(&rec.data[pos]);
    if hash_sha256(block) != h {
        return false;
    }
    service
        .lock()
        .unwrap()
        .store
        .replace(Space::UserBlock, user, &h, block)
        .is_ok()
}
