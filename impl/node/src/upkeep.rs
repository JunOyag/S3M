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

use p2p_storage_core::erasure::{encode_parity, padding_block, reconstruct_data};
use p2p_storage_core::symmetric_suite::hash_sha256;
use p2p_storage_protocol::dispersal::{by_xor_distance, Id};
use p2p_storage_protocol::exchange::{verify_receipt, Body, Refusal, Request, Response};
use serde::{Deserialize, Serialize};

use crate::blacklist::REASON_POS_INVALID;
use crate::chunk_store::Space;
use crate::dispersal_engine::{DispersalState, EngineConfig, Fabric, Retired, StripeRec};
use crate::exchange::NodeService;
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
    let me = service.lock().unwrap().node_id();
    let taken: HashSet<String> = rec.parity.iter().map(|(_, _, p)| p.clone()).collect();
    let mut candidates: Vec<Id> = fabric
        .partners()
        .iter()
        .map(|p| p.node_id)
        .filter(|p| !taken.contains(&hx(p)) && !up.is_blacklisted(p))
        .collect();
    by_xor_distance(&mut candidates, &id(&rec.id));
    let mut next = 0;
    let mut done = 0;
    for &i in indices {
        let Some(frag) = parity.get(i as usize - cfg.k) else {
            continue;
        };
        let h = hash_sha256(frag);
        while next < candidates.len() {
            let p = candidates[next];
            next += 1;
            if let Ok(sig) = fabric.store(&p, frag.clone()).await {
                if verify_receipt(&p, &h, &me, &sig) {
                    if let Some(st) = service.lock().unwrap().partners.get_mut(&p) {
                        st.ledger.hosted_for_partner += 1;
                    }
                    if let Some(slot) = rec.parity.iter_mut().find(|(x, _, _)| *x == i) {
                        retired.push(Retired {
                            at: now,
                            hash: slot.1.clone(),
                            partner: slot.2.clone(),
                        });
                        *slot = (i, hx(&h), hx(&p));
                    } else {
                        rec.parity.push((i, hx(&h), hx(&p)));
                    }
                    done += 1;
                    break;
                }
            }
        }
    }
    done
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
            let verdict = match answer {
                Ok(Ok(Response::ChallengeResponse(d))) => {
                    let d: Option<[u8; 32]> = d.try_into().ok();
                    match d {
                        Some(d) => judge(&expected, Some(&d)),
                        None => Verdict::Fraud,
                    }
                }
                // Fragment qu'il doit héberger introuvable : échec PoS.
                Ok(Ok(Response::Failure(Refusal::NotFound))) => Verdict::Fraud,
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

    // 2. Fraude : rupture et réparation immédiate.
    for p in &frauds {
        rupture(service, &mut up, p, now);
        report.frauds.push(*p);
    }
    let analysis_due = now >= up.last_analysis + ucfg.analysis_period_s;
    if analysis_due {
        up.last_analysis = now;
    }
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
                .filter(|(_, _, p)| frauds.contains(&id(p)) || up.retiring.contains(p))
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
                let placed: HashSet<u16> = rec.parity.iter().map(|(i, _, _)| *i).collect();
                let up_count = rec.parity.iter().filter(|(_, _, p)| available(p)).count();
                if up_count < cfg.k + 2 {
                    indices.extend(
                        (cfg.k..cfg.k * (1 + cfg.coef))
                            .map(|i| i as u16)
                            .filter(|i| !placed.contains(i)),
                    );
                }
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
            if n < indices.len() {
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
                    < cfg.k + 2
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
    if now >= up.last_scrub + ucfg.scrub_period_s {
        up.last_scrub = now;
        for user in &users {
            let uid = id(user);
            let stripes = state.users[user].stripes.clone();
            for rec in &stripes {
                for (pos, h) in rec.data.iter().enumerate() {
                    if rec.padding[pos] {
                        continue;
                    }
                    let ok = service
                        .lock()
                        .unwrap()
                        .store
                        .get(Space::UserBlock, &id(h))
                        .is_some_and(|(o, b)| o == uid && hx(&hash_sha256(&b)) == *h);
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
                        up.log(
                            now,
                            format!("bloc local {}… altéré, reconstruction impossible", &h[..12]),
                        );
                    }
                }
            }
        }
    }
    state.upkeep = up;
    report
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
