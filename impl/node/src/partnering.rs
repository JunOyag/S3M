//! Partenariats automatiques — id `protocols.partenariat-automatique`
//! (partie node). Réf. spec : docs/04-protocols/partenariat-automatique.md.
//!
//! Un cycle : découverte (DHT, entrée Node valide exigée), `Probe` des
//! candidats et partenaires, score fiabilité/disponibilité/vitesse,
//! propositions de partenariat tant que la cible n'est pas atteinte, retrait
//! des partenaires durablement sous le seuil, fin du partenariat une fois
//! leurs fragments replacés et purgés.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use libp2p::multiaddr::Protocol;
use libp2p::{identity, Multiaddr, PeerId};
use s3m_protocol::dispersal::Id;
use s3m_protocol::exchange::{Body, Request, Response};
use serde::{Deserialize, Serialize};

use crate::dht_directory::DhtNode;
use crate::dispersal_engine::DispersalState;
use crate::exchange::{
    entry_multiaddrs, node_id_of, subnet, BlockServer, NodeService, PartnerState, MAX_FAILURES,
};

/// Paramètres des partenariats automatiques.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PartneringConfig {
    pub enabled: bool,
    /// Partenaires actifs visés (0 : coef×k + 4).
    pub target_partners: usize,
    pub weight_reliability: f64,
    pub weight_availability: f64,
    pub weight_speed: f64,
    /// Latence de référence pour la vitesse (ms).
    pub reference_latency_ms: f64,
    /// Score minimal pour recevoir de nouveaux fragments.
    pub placement_threshold: f64,
    /// Sous ce score pendant `retire_after_s`, le partenaire est retiré.
    pub exit_threshold: f64,
    pub retire_after_s: u64,
    pub discovery_period_s: u64,
    pub probe_period_s: u64,
}

impl Default for PartneringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            target_partners: 0,
            weight_reliability: 0.5,
            weight_availability: 0.3,
            weight_speed: 0.2,
            reference_latency_ms: 200.0,
            placement_threshold: 0.5,
            exit_threshold: 0.35,
            retire_after_s: 7 * 86_400,
            discovery_period_s: 600,
            probe_period_s: 300,
        }
    }
}

/// État d'un pair connu.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Peer {
    pub addr: String,
    /// Autres adresses connues (QUIC, relais), essayées si `addr` échoue.
    #[serde(default)]
    pub alt_addrs: Vec<String>,
    pub ip: String,
    /// Moyenne glissante des réponses aux `Probe` (0..1).
    pub availability: f64,
    pub latency_ms: f64,
    pub probes: u64,
    pub answered: u64,
    pub accepting: bool,
    pub first_seen: u64,
    pub last_probe: u64,
    pub last_answer: u64,
    /// `candidat`, `partenaire`, `retrait`, `terminé`.
    pub status: String,
    pub below_since: Option<u64>,
    pub proposed_at: u64,
}

/// État des partenariats automatiques (persisté avec la dispersion).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PartneringState {
    pub peers: BTreeMap<String, Peer>,
    pub last_discovery: u64,
    pub events: Vec<String>,
}

const MAX_EVENTS: usize = 50;

impl PartneringState {
    fn log(&mut self, now: u64, msg: String) {
        self.events.push(format!("{now} {msg}"));
        let n = self.events.len();
        if n > MAX_EVENTS {
            self.events.drain(..n - MAX_EVENTS);
        }
    }
}

/// Composantes du score.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Score {
    pub reliability: f64,
    pub availability: f64,
    pub speed: f64,
    pub total: f64,
}

/// Score d'un pair : `pos_ok` / `pos_fail` = challenges réussis / sans
/// réponse (`upkeep`).
pub fn score(cfg: &PartneringConfig, p: &Peer, pos_ok: u64, pos_fail: u64) -> Score {
    let reliability = (pos_ok as f64 + 1.0) / ((pos_ok + pos_fail) as f64 + 2.0);
    let availability = if p.probes == 0 { 0.5 } else { p.availability };
    let speed = if p.answered == 0 || p.latency_ms <= 0.0 {
        0.5
    } else {
        (cfg.reference_latency_ms / p.latency_ms).min(1.0)
    };
    let w = cfg.weight_reliability + cfg.weight_availability + cfg.weight_speed;
    let total = if w <= 0.0 {
        0.0
    } else {
        (cfg.weight_reliability * reliability
            + cfg.weight_availability * availability
            + cfg.weight_speed * speed)
            / w
    };
    Score {
        reliability,
        availability,
        speed,
        total,
    }
}

fn hx(b: &[u8]) -> String {
    hex::encode(b)
}

fn id(s: &str) -> Option<Id> {
    hex::decode(s).ok()?.try_into().ok()
}

/// Multiaddr d'échange de blocs depuis `ip:port` et l'identité du Nœud.
pub fn multiaddr(node_id: &Id, ip: &str, port: u16) -> Option<String> {
    let pk = identity::ed25519::PublicKey::try_from_bytes(node_id).ok()?;
    let peer = PeerId::from(identity::PublicKey::from(pk));
    let ip: std::net::IpAddr = ip.parse().ok()?;
    let mut a = Multiaddr::empty();
    a.push(match ip {
        std::net::IpAddr::V4(v) => Protocol::Ip4(v),
        std::net::IpAddr::V6(v) => Protocol::Ip6(v),
    });
    a.push(Protocol::Tcp(port));
    a.push(Protocol::P2p(peer));
    Some(a.to_string())
}

/// IP d'une multiaddr (hors adresses via relais : IP du relais).
pub fn ip_of(a: &str) -> Option<String> {
    let m: Multiaddr = a.parse().ok()?;
    if m.iter().any(|p| matches!(p, Protocol::P2pCircuit)) {
        return None;
    }
    m.iter().find_map(|p| match p {
        Protocol::Ip4(v) => Some(v.to_string()),
        Protocol::Ip6(v) => Some(v.to_string()),
        _ => None,
    })
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("CSPRNG du système");
    b
}

/// Bilan d'un cycle.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PartneringReport {
    pub discovered: usize,
    pub probed: usize,
    pub proposed: usize,
    pub accepted: usize,
    pub retiring: usize,
    pub ended: usize,
}

/// Contexte réseau d'un cycle.
pub struct Net<'a> {
    pub server: &'a BlockServer,
    pub dht: &'a DhtNode,
    pub addrs: &'a Mutex<std::collections::HashMap<Id, String>>,
    /// Entrée DHT Node publiée (jointe aux propositions).
    pub own_entry: Option<Vec<u8>>,
}

/// Met en tête une adresse TCP du même réseau local (même /24 qu'une
/// adresse locale de `own`) : deux Nœuds derrière la même box se joignent
/// sans passer par elle (`network.traversee-nat`).
pub fn lan_first(addrs: &mut Vec<String>, own: &[String]) {
    let prefix = |a: &str| -> Option<[u8; 3]> {
        match a.parse::<Multiaddr>().ok()?.iter().next()? {
            Protocol::Ip4(v) if v.is_private() => {
                let o = v.octets();
                Some([o[0], o[1], o[2]])
            }
            _ => None,
        }
    };
    let mine: Vec<[u8; 3]> = own.iter().filter_map(|a| prefix(a)).collect();
    if let Some(i) = addrs
        .iter()
        .position(|a| !a.contains("/quic") && prefix(a).is_some_and(|p| mine.contains(&p)))
    {
        let a = addrs.remove(i);
        addrs.insert(0, a);
    }
}

/// Partenaires exclus des nouveaux placements (score bas ou retrait).
pub fn excluded(cfg: &PartneringConfig, state: &DispersalState) -> HashSet<Id> {
    state
        .partnering
        .peers
        .iter()
        .filter(|(_, p)| p.status == "partenaire" || p.status == "retrait")
        .filter(|(n, p)| {
            let (ok, fail) = pos_counts(state, n);
            p.status == "retrait" || score(cfg, p, ok, fail).total < cfg.placement_threshold
        })
        .filter_map(|(n, _)| id(n))
        .collect()
}

fn pos_counts(state: &DispersalState, node: &str) -> (u64, u64) {
    (
        state.upkeep.pos_ok.get(node).copied().unwrap_or(0),
        state.upkeep.pos_fail.get(node).copied().unwrap_or(0),
    )
}

/// Fragments encore confiés à `node` (catalogues, snapshot, purges en attente).
fn holds_fragments(state: &DispersalState, node: &str) -> bool {
    let stripes = state
        .users
        .values()
        .flat_map(|u| u.stripes.iter().chain(u.index.iter()))
        .chain(state.snapshot.stripe.iter());
    let retired = state
        .users
        .values()
        .flat_map(|u| u.retired.iter())
        .chain(state.snapshot.retired.iter());
    stripes
        .flat_map(|s| s.parity.iter())
        .any(|(_, _, p)| p == node)
        || retired.into_iter().any(|r| r.partner == node)
}

/// Un cycle de partenariats automatiques.
pub async fn run_partnering(
    service: &Mutex<NodeService>,
    state: &mut DispersalState,
    net: &Net<'_>,
    cfg: &PartneringConfig,
    target_default: usize,
    now: u64,
) -> PartneringReport {
    let mut report = PartneringReport::default();
    let me = service.lock().unwrap().node_id();
    service.lock().unwrap().ramp_trust(now);
    let mut st = std::mem::take(&mut state.partnering);

    // Partenariats acceptés à la demande d'autres Nœuds.
    let own = net
        .own_entry
        .as_deref()
        .map(|e| entry_multiaddrs(&me, e))
        .unwrap_or_default();
    let inbound = std::mem::take(&mut service.lock().unwrap().new_partners);
    for (n, mut addrs) in inbound {
        lan_first(&mut addrs, &own);
        if !addrs.is_empty() {
            let a = addrs.remove(0);
            net.addrs.lock().unwrap().insert(n, a.clone());
            let p = st.peers.entry(hx(&n)).or_default();
            p.ip = ip_of(&a).unwrap_or_default();
            p.addr = a;
            p.alt_addrs = addrs;
            p.status = "partenaire".into();
            p.first_seen = p.first_seen.max(1).min(now);
            st.log(
                now,
                format!("partenariat accepté (demande de {}…)", &hx(&n)[..12]),
            );
        }
    }
    // Partenaires déclarés à la main : suivis aussi.
    {
        let s = service.lock().unwrap();
        let addrs = net.addrs.lock().unwrap();
        for n in s.partners.keys() {
            let p = st.peers.entry(hx(n)).or_default();
            if p.status.is_empty() || p.status == "candidat" || p.status == "terminé" {
                p.status = "partenaire".into();
            }
            if let Some(a) = addrs.get(n) {
                p.addr = a.clone();
                if let Ok(m) = a.parse::<Multiaddr>() {
                    if let Some(Protocol::Ip4(v)) = m.iter().next() {
                        p.ip = v.to_string();
                    }
                }
            }
        }
    }

    // 1. Découverte.
    if cfg.enabled && now >= st.last_discovery + cfg.discovery_period_s {
        st.last_discovery = now;
        let peers = net
            .dht
            .closest_peers(random::<32>().to_vec())
            .await
            .unwrap_or_default();
        for peer in peers.iter().take(64) {
            let Some(n) = node_id_of(peer) else { continue };
            if n == me || st.peers.contains_key(&hx(&n)) || state.upkeep.is_blacklisted(&n) {
                continue;
            }
            // Entrée Node valide (preuve VDF vérifiée par l'adaptateur DHT).
            let Some(env) = net.dht.get(n.to_vec()).await.ok().flatten() else {
                continue;
            };
            let mut addrs = entry_multiaddrs(&n, &env);
            lan_first(&mut addrs, &own);
            if addrs.is_empty() {
                continue;
            }
            let addr = addrs.remove(0);
            st.peers.insert(
                hx(&n),
                Peer {
                    ip: ip_of(&addr).unwrap_or_default(),
                    addr,
                    alt_addrs: addrs,
                    status: "candidat".into(),
                    first_seen: now,
                    ..Default::default()
                },
            );
            report.discovered += 1;
        }
        if report.discovered > 0 {
            st.log(
                now,
                format!("{} candidat(s) découvert(s)", report.discovered),
            );
        }
    }

    // 2. Probe.
    let due: Vec<String> = st
        .peers
        .iter()
        .filter(|(_, p)| {
            p.status != "terminé" && !p.addr.is_empty() && now >= p.last_probe + cfg.probe_period_s
        })
        .map(|(n, _)| n.clone())
        .take(32)
        .collect();
    for n in due {
        let Some(p) = st.peers.get_mut(&n) else {
            continue;
        };
        let Ok(addr) = p.addr.parse::<Multiaddr>() else {
            continue;
        };
        let nonce = random::<16>().to_vec();
        let t0 = Instant::now();
        let req = Request {
            credential: None,
            body: Body::Probe {
                nonce: nonce.clone(),
            },
        };
        let answer =
            tokio::time::timeout(Duration::from_secs(5), net.server.request(addr, req)).await;
        p.probes += 1;
        p.last_probe = now;
        let ok = match answer {
            Ok(Ok(Response::ProbeReply {
                nonce: back,
                accepting_partners,
                ..
            })) if back == nonce => {
                p.accepting = accepting_partners;
                true
            }
            _ => false,
        };
        if !ok && !p.alt_addrs.is_empty() {
            // Adresse suivante au prochain essai (directe, QUIC, relais).
            let next = p.alt_addrs.remove(0);
            let old = std::mem::replace(&mut p.addr, next);
            p.alt_addrs.push(old);
        }
        let a = if p.probes == 1 {
            if ok {
                1.0
            } else {
                0.0
            }
        } else {
            p.availability
        };
        p.availability = a + (if ok { 1.0 } else { 0.0 } - a) / 16.0;
        if ok {
            let ms = t0.elapsed().as_secs_f64() * 1_000.0;
            p.latency_ms = if p.answered == 0 {
                ms
            } else {
                p.latency_ms + (ms - p.latency_ms) / 8.0
            };
            p.answered += 1;
            p.last_answer = now;
        }
        report.probed += 1;
    }

    // 3. Retrait et fin des partenariats faibles.
    let names: Vec<String> = st.peers.keys().cloned().collect();
    for n in &names {
        let (ok, fail) = pos_counts(state, n);
        let p = st.peers.get_mut(n).unwrap();
        if p.status != "partenaire" && p.status != "retrait" {
            continue;
        }
        let failures = id(n)
            .and_then(|nid| service.lock().unwrap().partners.get(&nid).map(|s| s.failures))
            .unwrap_or(0);
        if failures >= MAX_FAILURES && p.status == "partenaire" {
            p.status = "retrait".into();
            report.retiring += 1;
            state.upkeep.retiring.insert(n.clone());
            st.log(now, format!("retrait de {}… ({failures} manquements)", &n[..12]));
            continue;
        }
        let s = score(cfg, p, ok, fail).total;
        if s >= cfg.exit_threshold && p.status == "partenaire" {
            p.below_since = None;
            continue;
        }
        if s >= cfg.exit_threshold && failures < MAX_FAILURES {
            p.below_since = None;
            if p.status == "retrait" {
                p.status = "partenaire".into();
            }
            continue;
        }
        let since = *p.below_since.get_or_insert(now);
        if p.status == "partenaire" && cfg.enabled && now >= since + cfg.retire_after_s {
            p.status = "retrait".into();
            report.retiring += 1;
            state.upkeep.retiring.insert(n.clone());
            st.log(now, format!("retrait de {}… (score {s:.2})", &n[..12]));
        }
    }
    for n in &names {
        if st.peers[n].status == "retrait" && !holds_fragments(state, n) {
            if let Some(nid) = id(n) {
                service.lock().unwrap().partners.remove(&nid);
            }
            state.upkeep.retiring.remove(n);
            st.peers.get_mut(n).unwrap().status = "terminé".into();
            report.ended += 1;
            st.log(now, format!("fin du partenariat avec {}…", &n[..12]));
        }
    }

    // 4. Recrutement.
    // Cible réglée (coef×k au moins), relevée des partenaires manquants.
    let base = if cfg.target_partners == 0 {
        target_default
    } else {
        cfg.target_partners
    };
    let missing = service.lock().unwrap().missing_partners;
    let target = base.max(crate::dispersal_engine::K * crate::dispersal_engine::COEF) + missing;
    let active = st
        .peers
        .values()
        .filter(|p| p.status == "partenaire")
        .count();
    let pol = service.lock().unwrap().partner_policy;
    // Sous-réseaux des partenaires actifs (diversité des adresses).
    {
        let mut s = service.lock().unwrap();
        let nets: HashMap<Id, String> = st
            .peers
            .iter()
            .filter(|(_, p)| p.status == "partenaire" || p.status == "retrait")
            .filter_map(|(n, p)| Some((id(n)?, subnet(&p.ip)?)))
            .collect();
        s.subnets = nets;
    }
    let crowded = |st: &PartneringState, ip: &str| {
        pol.subnet_limit > 0
            && subnet(ip).is_some_and(|n| {
                st.peers
                    .values()
                    .filter(|p| p.status == "partenaire" || p.status == "retrait")
                    .filter(|p| subnet(&p.ip).as_deref() == Some(n.as_str()))
                    .count()
                    >= pol.subnet_limit
            })
    };
    if cfg.enabled && active < target {
        if let Some(entry) = &net.own_entry {
            let snapshot = st.clone();
            let mut cands: Vec<(f64, String)> = st
                .peers
                .iter()
                .filter(|(_, p)| {
                    p.status == "candidat"
                        && p.accepting
                        && now >= p.proposed_at + 3_600
                        && !crowded(&snapshot, &p.ip)
                })
                .map(|(n, p)| {
                    let (ok, fail) = pos_counts(state, n);
                    (score(cfg, p, ok, fail).total, n.clone())
                })
                .filter(|(s, _)| *s >= cfg.placement_threshold)
                .collect();
            cands.sort_by(|a, b| b.0.total_cmp(&a.0));
            for (_, n) in cands.into_iter().take(target - active) {
                if crowded(&st, &st.peers[&n].ip) {
                    continue;
                }
                let p = st.peers.get_mut(&n).unwrap();
                p.proposed_at = now;
                let Ok(addr) = p.addr.parse::<Multiaddr>() else {
                    continue;
                };
                let req = Request {
                    credential: None,
                    body: Body::ProposePartnership {
                        allowance_blocks: pol.promise(&PartnerState::default()),
                        node_entry: entry.clone(),
                    },
                };
                report.proposed += 1;
                if let Ok(Response::PartnershipAnswer { granted_blocks }) =
                    net.server.request(addr, req).await
                {
                    if granted_blocks > 0 {
                        let Some(nid) = id(&n) else { continue };
                        {
                            let mut s = service.lock().unwrap();
                            s.partners.insert(
                                nid,
                                PartnerState {
                                    last_seen: now,
                                    trust_since: now,
                                    ..Default::default()
                                },
                            );
                            s.set_quota(&nid, granted_blocks, now);
                        }
                        net.addrs.lock().unwrap().insert(nid, p.addr.clone());
                        p.status = "partenaire".into();
                        report.accepted += 1;
                        st.log(now, format!("nouveau partenaire {}…", &n[..12]));
                    }
                }
            }
        }
    }
    // 5. Renégociation des quotas (`protocols.partenariat-automatique#negociation`).
    if let Some(entry) = &net.own_entry {
        let due: Vec<(Id, u64)> = {
            let s = service.lock().unwrap();
            s.partners
                .iter()
                .filter(|(_, p)| now >= p.negotiated_at + cfg.discovery_period_s)
                .map(|(n, p)| (*n, s.partner_policy.promise(p)))
                .take(32)
                .collect()
        };
        for (nid, allowance) in due {
            let Some(addr) = net
                .addrs
                .lock()
                .unwrap()
                .get(&nid)
                .and_then(|a| a.parse::<Multiaddr>().ok())
            else {
                continue;
            };
            let req = Request {
                credential: None,
                body: Body::ProposePartnership {
                    allowance_blocks: allowance,
                    node_entry: entry.clone(),
                },
            };
            let answer =
                tokio::time::timeout(Duration::from_secs(5), net.server.request(addr, req)).await;
            if let Ok(Ok(Response::PartnershipAnswer { granted_blocks })) = answer {
                if granted_blocks > 0 {
                    service.lock().unwrap().set_quota(&nid, granted_blocks, now);
                }
            }
        }
    }
    state.partnering = st;
    report
}
