//! Espace de secours — id `protocols.espace-secours`, partie `node`
//! (Phase 4). Réf. spec : docs/04-protocols/espace-secours.md.
//!
//! - **En tant que partenaire de secours** : un Nœud accepte des dépôts
//!   d'urgence de tiers dans la limite de `U_backup` déposants,
//!   `E_secours = U_backup × Q_max / n_secours` octets et
//!   `Q_max / n_secours` par déposant ; une identité VDF ne tient qu'une
//!   clé de secours à la fois ; libération signée, sans rejeu ; purge des
//!   dépôts oubliés après 15 552 000 s.
//! - **Au retour du Nœud hébergeur** : il recalcule `emergency_dht_key` pour
//!   chaque Utilisateur rattaché, récupère les blocs et les intègre par
//!   timestamp croissant dans la limite du quota (même règle que
//!   `protocols.quota-sync`), puis calcule et disperse la parité.

use std::collections::BTreeMap;

use s3m_protocol::dht::emergency_dht_key;
use serde::{Deserialize, Serialize};

use crate::quota_sync::{integrate, Integration, PendingWrite};

/// Durée de conservation d'un dépôt jamais libéré (6 mois).
pub const DEPOSIT_RETENTION_S: u64 = 15_552_000;
const GIB: u64 = 1 << 30;

/// Erreurs d'admission.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReservationError {
    #[error("capacité d'accueil U_backup atteinte")]
    TooManyUsers,
    #[error("espace réservé au secours épuisé")]
    NoSpace,
    #[error("identité VDF déjà liée à une autre clé de secours")]
    IdentityInUse,
}

/// Dépôt d'un Utilisateur en détresse, identifié par sa clé de secours.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Depositor {
    pub bytes: u64,
    /// `sig_pub_user` (hex) de l'identité VDF qui a déposé.
    #[serde(default)]
    pub identity: String,
    #[serde(default)]
    pub last_deposit: u64,
    /// Dernier `timestamp` de libération appliqué.
    #[serde(default)]
    pub last_release: u64,
}

fn default_max_users() -> u32 {
    20
}
fn default_per_depositor() -> u64 {
    GIB
}

/// Réserve d'accueil pour tiers en détresse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyReserve {
    /// `U_backup`.
    #[serde(default = "default_max_users")]
    pub max_users: u32,
    /// `E_secours`.
    pub reserved_bytes: u64,
    /// `Q_max / n_secours`.
    #[serde(default = "default_per_depositor")]
    pub per_depositor_bytes: u64,
    /// Par `emergency_pub` (hex).
    #[serde(default)]
    depositors: BTreeMap<String, Depositor>,
}

impl Default for EmergencyReserve {
    /// Valeurs par défaut : `U_backup = 20`, 1 Gio par déposant, 20 Gio.
    fn default() -> Self {
        Self::with_cap(20, GIB)
    }
}

impl EmergencyReserve {
    /// Réserve sans plafond par déposant.
    pub fn new(max_users: u32, reserved_bytes: u64) -> Self {
        Self {
            max_users,
            reserved_bytes,
            per_depositor_bytes: u64::MAX,
            depositors: BTreeMap::new(),
        }
    }

    /// Réserve dimensionnée : `E_secours = U_backup × par déposant`.
    pub fn with_cap(max_users: u32, per_depositor_bytes: u64) -> Self {
        Self {
            max_users,
            reserved_bytes: u64::from(max_users).saturating_mul(per_depositor_bytes),
            per_depositor_bytes,
            depositors: BTreeMap::new(),
        }
    }

    /// Change les limites (les dépôts en place sont conservés).
    pub fn set_limits(&mut self, max_users: u32, per_depositor_bytes: u64) {
        self.max_users = max_users;
        self.per_depositor_bytes = per_depositor_bytes;
        self.reserved_bytes = u64::from(max_users).saturating_mul(per_depositor_bytes);
    }

    /// Accepte un dépôt de `bytes` pour l'Utilisateur `user` (identifié par
    /// sa clé de secours, jamais par un Connecteur).
    pub fn accept(&mut self, user: [u8; 32], bytes: u64) -> Result<(), ReservationError> {
        let k = hex::encode(user);
        if !self.depositors.contains_key(&k) && self.depositors.len() as u32 >= self.max_users {
            return Err(ReservationError::TooManyUsers);
        }
        if self.used_bytes() + bytes > self.reserved_bytes {
            return Err(ReservationError::NoSpace);
        }
        let d = self.depositors.entry(k).or_default();
        if d.bytes + bytes > self.per_depositor_bytes {
            if d.bytes == 0 {
                self.depositors.remove(&hex::encode(user));
            }
            return Err(ReservationError::NoSpace);
        }
        d.bytes += bytes;
        Ok(())
    }

    /// Dépôt par l'identité VDF `identity` : une seule clé de secours par
    /// identité tant qu'elle a des blocs.
    pub fn admit(
        &mut self,
        user: [u8; 32],
        identity: &[u8; 32],
        bytes: u64,
        now: u64,
    ) -> Result<(), ReservationError> {
        let (k, id) = (hex::encode(user), hex::encode(identity));
        if self
            .depositors
            .iter()
            .any(|(o, d)| *o != k && d.identity == id && d.bytes > 0)
        {
            return Err(ReservationError::IdentityInUse);
        }
        self.accept(user, bytes)?;
        let d = self.depositors.get_mut(&k).expect("accepté");
        d.identity = id;
        d.last_deposit = now;
        Ok(())
    }

    /// Annule ou libère `bytes` du dépôt de `user`.
    pub fn freed(&mut self, user: &[u8; 32], bytes: u64) {
        let k = hex::encode(user);
        if let Some(d) = self.depositors.get_mut(&k) {
            d.bytes = d.bytes.saturating_sub(bytes);
            if d.bytes == 0 {
                self.depositors.remove(&k);
            }
        }
    }

    /// Libération signée de `timestamp` : refusée si elle n'est pas plus
    /// récente que la dernière appliquée.
    pub fn check_release(&mut self, user: &[u8; 32], timestamp: u64) -> bool {
        match self.depositors.get_mut(&hex::encode(user)) {
            Some(d) if timestamp <= d.last_release => false,
            Some(d) => {
                d.last_release = timestamp;
                true
            }
            None => true,
        }
    }

    /// Libération complète (purge).
    pub fn release(&mut self, user: &[u8; 32]) {
        self.depositors.remove(&hex::encode(user));
    }

    /// Dépôts sans nouvelle depuis `DEPOSIT_RETENTION_S`.
    pub fn expired(&self, now: u64) -> Vec<[u8; 32]> {
        self.depositors
            .iter()
            .filter(|(_, d)| d.last_deposit + DEPOSIT_RETENTION_S <= now)
            .filter_map(|(k, _)| hex::decode(k).ok()?.try_into().ok())
            .collect()
    }

    /// Recale l'occupation sur le stockage (`(déposant, octets)`) au
    /// démarrage.
    pub fn rebuild(&mut self, stored: &[([u8; 32], u64)], now: u64) {
        self.depositors
            .retain(|k, _| stored.iter().any(|(u, b)| hex::encode(u) == *k && *b > 0));
        for (u, b) in stored.iter().filter(|(_, b)| *b > 0) {
            let d = self.depositors.entry(hex::encode(u)).or_default();
            d.bytes = *b;
            if d.last_deposit == 0 {
                d.last_deposit = now;
            }
        }
    }

    pub fn users(&self) -> usize {
        self.depositors.len()
    }

    pub fn used_bytes(&self) -> u64 {
        self.depositors.values().map(|d| d.bytes).sum()
    }

    /// Déposants (clé de secours hex, dépôt).
    pub fn depositors(&self) -> impl Iterator<Item = (&String, &Depositor)> {
        self.depositors.iter()
    }
}

/// Clés DHT à consulter au retour : une par Utilisateur rattaché, dérivée
/// de son `K_attach`.
pub fn emergency_keys(attached_k_attach: &[[u8; 32]]) -> Vec<[u8; 32]> {
    attached_k_attach.iter().map(emergency_dht_key).collect()
}

/// Intégration au retour : blocs de secours par timestamp croissant,
/// jusqu'au quota libre de l'Utilisateur.
pub fn integrate_emergency(
    writes: Vec<PendingWrite>,
    free_blocks: u64,
    already_stored: &dyn Fn(&[u8; 32]) -> bool,
) -> Integration {
    integrate(writes, free_blocks, already_stored)
}

/// Bilan d'un tour d'intégration au retour.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ReturnReport {
    /// Entrées de secours trouvées à intégrer.
    pub entries: usize,
    pub integrated: u64,
    /// Blocs refusés faute de quota.
    pub over_quota: u64,
    /// Blocs introuvables chez les partenaires (nouvel essai plus tard).
    pub missing: u64,
}

async fn emergency_block(
    fabric: &crate::dispersal_engine::NetFabric,
    m: &s3m_protocol::emergency::Manifest,
    partner: &[u8; 32],
    depositor: &[u8; 32],
    hash: &[u8; 32],
) -> Option<Vec<u8>> {
    use s3m_protocol::exchange::{Body, Request, Response};
    let mut addrs: Vec<String> = m
        .partners
        .iter()
        .filter(|p| p.node_id == *partner)
        .filter_map(|p| crate::partnering::multiaddr(partner, &p.ip, p.port))
        .collect();
    if let Some(env) = fabric.dht.get(partner.to_vec()).await.ok().flatten() {
        addrs.extend(crate::exchange::entry_multiaddrs(partner, &env));
    }
    for a in addrs {
        let Ok(addr) = a.parse() else { continue };
        let req = Request {
            credential: None,
            body: Body::EmergencyGet {
                emergency_pub: depositor.to_vec(),
                hash: hash.to_vec(),
            },
        };
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            fabric.server.request(addr, req),
        )
        .await;
        if let Ok(Ok(Response::BlockData(d))) = r {
            if s3m_core::symmetric_suite::hash_sha256(&d) == *hash {
                return Some(d);
            }
        }
    }
    None
}

/// Au retour : pour chaque Utilisateur rattaché, lit son entrée de secours
/// dans la DHT et intègre les blocs déposés, dans la limite de son quota
/// et dans l'ordre des dépôts. `seen` : dernière séquence entièrement
/// traitée par Utilisateur.
pub async fn integrate_returns(
    fabric: &crate::dispersal_engine::NetFabric,
    seen: &mut std::collections::HashMap<[u8; 32], u64>,
) -> ReturnReport {
    use s3m_protocol::emergency::{emergency_keys as keys_of, open_emergency_entry};
    let (priv_node, users): (_, Vec<_>) = {
        let s = fabric.service.lock().unwrap();
        (
            s.priv_node(),
            s.users
                .iter()
                .map(|(u, a)| (*u, a.salt.clone(), a.root))
                .collect(),
        )
    };
    let mut r = ReturnReport::default();
    for (u, salt, root) in users {
        let Ok(k) = s3m_core::k_attach::derive_k_attach_as_node(&priv_node, &u, &salt) else {
            continue;
        };
        let key = emergency_dht_key(&k);
        let Some(env) = fabric.dht.get(key.to_vec()).await.ok().flatten() else {
            continue;
        };
        let (Ok((seq, m)), Ok(keys)) = (open_emergency_entry(&k, &env), keys_of(&k)) else {
            continue;
        };
        if seen.get(&u) == Some(&seq) {
            continue;
        }
        if m.pending_root(&root).is_none() {
            // Déjà réconciliée ou construite sur une autre racine.
            seen.insert(u, seq);
            continue;
        }
        r.entries += 1;
        let mut complete = true;
        for (h, partner) in &m.blocks {
            if fabric.service.lock().unwrap().store.contains(h) {
                continue;
            }
            let Some(d) = emergency_block(fabric, &m, partner, &keys.sig_pub, h).await else {
                r.missing += 1;
                complete = false;
                continue;
            };
            match fabric.service.lock().unwrap().put_user_block(&u, &d) {
                Ok(_) => r.integrated += 1,
                Err(s3m_protocol::exchange::Refusal::QuotaExceeded) => r.over_quota += 1,
                Err(_) => complete = false,
            }
        }
        if complete {
            seen.insert(u, seq);
        }
    }
    r
}
