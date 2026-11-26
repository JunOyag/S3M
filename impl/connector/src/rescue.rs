//! Lecture de secours — `protocols.integrite-lecture` (chemin de secours) et
//! `protocols.echange-blocs` § Autorisation de secours, partie `connector`.
//!
//! Nœud injoignable : le Connecteur lit son `DispersalManifest` dans la DHT
//! (`K_attach`, qu'il partage avec son Nœud), parcourt l'arbre d'index pour
//! situer le bloc demandé, puis le reconstruit (Reed-Solomon) depuis k
//! fragments de parité demandés aux partenaires sous son autorisation de
//! secours. Lecture seule ; l'index est gardé quelques minutes, les blocs
//! des derniers stripes reconstruits aussi.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use libp2p::multiaddr::Protocol;
use libp2p::{identity, Multiaddr, PeerId};
use s3m_core::erasure::{padding_block, reconstruct_data};
use s3m_core::k_dispersal::derive_k_dispersal_content;
use s3m_core::symmetric_suite::hash_sha256;
use s3m_core::version::CURRENT_HEADER;
use s3m_protocol::dht::dispersal_dht_key;
use s3m_protocol::dispersal::{
    decode_index_node, decode_manifest, open_dispersal_entry, PartnerDesc, StripeDesc,
};
use s3m_protocol::index::open_index_node;

use crate::daemon::Shared;
use crate::fs::BlockHash;

/// Coefficient de redondance (parité = coef×k), constante du protocole.
const COEF: usize = 3;
/// Durée de validité de l'index relu.
const INDEX_TTL_S: u64 = 300;
/// Blocs reconstruits gardés (les voisins d'un stripe servent souvent).
const CACHE_BLOCKS: usize = 256;

type Located = (StripeDesc, Arc<Vec<PartnerDesc>>);
/// Index relu : `(instant, bloc → stripe)`.
type Index = Option<(u64, Arc<HashMap<BlockHash, Located>>)>;

/// Lecture de secours d'un Connecteur.
#[derive(Default)]
pub struct Rescue {
    shared: OnceLock<Weak<Shared>>,
    index: Mutex<Index>,
    cache: Mutex<Vec<(BlockHash, Vec<u8>)>>,
    addrs: Mutex<HashMap<[u8; 32], Multiaddr>>,
    /// Partenaires du catalogue de dispersion (dernier index relu).
    partners: Mutex<Vec<PartnerDesc>>,
    /// Blocs servis par reconstruction.
    pub served: AtomicU64,
    pub last_error: Mutex<Option<String>>,
    /// Dernier échec de reconstruction (pause, voir `daemon::RESCUE_HOLD`).
    pub down: Mutex<Option<std::time::Instant>>,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn peer_of(node_id: &[u8; 32]) -> Option<PeerId> {
    let pk = identity::ed25519::PublicKey::try_from_bytes(node_id).ok()?;
    Some(identity::PublicKey::from(pk).to_peer_id())
}

/// Adresse déclarée d'un partenaire dans le catalogue (ip, port).
fn desc_addr(p: &PartnerDesc) -> Option<Multiaddr> {
    let ip: std::net::IpAddr = p.ip.parse().ok()?;
    let mut m = Multiaddr::empty();
    m.push(match ip {
        std::net::IpAddr::V4(v) => Protocol::Ip4(v),
        std::net::IpAddr::V6(v) => Protocol::Ip6(v),
    });
    m.push(Protocol::Tcp(p.port));
    m.push(Protocol::P2p(peer_of(&p.node_id)?));
    Some(m)
}

impl Rescue {
    /// Échec récent : lecture de secours suspendue.
    pub fn is_down(&self) -> bool {
        self.down
            .lock()
            .unwrap()
            .is_some_and(|t| t.elapsed() < crate::daemon::RESCUE_HOLD)
    }

    pub fn attach(&self, sh: Weak<Shared>) {
        let _ = self.shared.set(sh);
    }

    /// Bloc reconstruit depuis la parité (appel asynchrone).
    pub async fn get(&self, hash: &BlockHash) -> Option<Vec<u8>> {
        if let Some((_, b)) = self.cache.lock().unwrap().iter().find(|(h, _)| h == hash) {
            return Some(b.clone());
        }
        let sh = self.shared.get()?.upgrade()?;
        match self.get_inner(&sh, hash).await {
            Ok(b) => {
                self.served.fetch_add(1, Ordering::Relaxed);
                *self.last_error.lock().unwrap() = None;
                Some(b)
            }
            Err(e) => {
                *self.last_error.lock().unwrap() = Some(e);
                None
            }
        }
    }

    async fn get_inner(&self, sh: &Shared, hash: &BlockHash) -> Result<Vec<u8>, String> {
        let index = self.index(sh, false).await?;
        let (stripe, table) = match index.get(hash) {
            Some(x) => x.clone(),
            // Bloc plus récent que l'index gardé : relecture.
            None => self
                .index(sh, true)
                .await?
                .get(hash)
                .cloned()
                .ok_or("bloc absent du catalogue de dispersion")?,
        };
        let data = self.data(sh, &stripe, &table).await?;
        let mut cache = self.cache.lock().unwrap();
        for d in &data {
            let h = hash_sha256(d);
            if !cache.iter().any(|(x, _)| *x == h) {
                cache.push((h, d.clone()));
            }
        }
        let over = cache.len().saturating_sub(CACHE_BLOCKS);
        cache.drain(..over);
        data.into_iter()
            .find(|d| hash_sha256(d) == *hash)
            .ok_or_else(|| "bloc reconstruit incohérent".into())
    }

    /// Bloc → stripe qui le porte, d'après le catalogue de dispersion.
    async fn index(
        &self,
        sh: &Shared,
        reload: bool,
    ) -> Result<Arc<HashMap<BlockHash, Located>>, String> {
        let t = now();
        if !reload {
            if let Some((at, m)) = self.index.lock().unwrap().as_ref() {
                if t < at + INDEX_TTL_S {
                    return Ok(m.clone());
                }
            }
        }
        let (kdc, manifest) = self.manifest(sh).await?;
        let table = Arc::new(manifest.partners.clone());
        let mut map = HashMap::new();
        let mut level = vec![manifest.root];
        while let Some(node) = level.pop() {
            for s in node.entries {
                if node.is_leaf {
                    for b in s
                        .blocks
                        .iter()
                        .filter(|b| (b.index as usize) < s.k as usize && !b.is_padding)
                    {
                        map.insert(b.hash, (s.clone(), table.clone()));
                    }
                } else {
                    let data = self.data(sh, &s, &table).await?;
                    let salt = s.encryption_salt.ok_or("stripe d'index sans sel")?;
                    let clear = open_index_node(&kdc, &salt, &CURRENT_HEADER, &data[0])
                        .map_err(|e| e.to_string())?;
                    level.push(decode_index_node(&clear).map_err(|e| e.to_string())?);
                }
            }
        }
        let map = Arc::new(map);
        *self.index.lock().unwrap() = Some((t, map.clone()));
        Ok(map)
    }

    /// Catalogue de dispersion publié par le Nœud (racine seule).
    async fn manifest(
        &self,
        sh: &Shared,
    ) -> Result<([u8; 32], s3m_protocol::dispersal::ManifestDesc), String> {
        let dht = sh.dht.get().ok_or("annuaire (DHT) pas encore joint")?;
        let k_attach = sh.session.k_attach();
        let kdc = derive_k_dispersal_content(&k_attach).map_err(|e| e.to_string())?;
        let env = dht
            .get(dispersal_dht_key(&k_attach).to_vec())
            .await
            .map_err(|e| e.to_string())?
            .ok_or("aucun catalogue de dispersion publié par le Nœud")?;
        let pointer = open_dispersal_entry(&k_attach, &env).map_err(|e| e.to_string())?;
        let root = self
            .data(sh, &pointer.root_stripe, &pointer.partners)
            .await?;
        let clear = open_index_node(&kdc, &pointer.salt, &CURRENT_HEADER, &root[0])
            .map_err(|e| e.to_string())?;
        let manifest = decode_manifest(&clear).map_err(|e| e.to_string())?;
        *self.partners.lock().unwrap() = manifest.partners.clone();
        Ok((kdc, manifest))
    }

    /// Nombre de partenaires du Nœud qui hébergent les stripes de cet
    /// Utilisateur (catalogue de dispersion relu, racine seule).
    pub async fn dispersal_partners(&self, sh: &Shared) -> Result<usize, String> {
        Ok(self.manifest(sh).await?.1.partners.len())
    }

    /// Partenaires en ligne parmi ceux qui hébergent la parité :
    /// `(en ligne, total)` ; erreur si le catalogue est illisible (annuaire
    /// injoignable : hors réseau).
    pub async fn partners_online(&self, sh: &Shared) -> Result<(usize, usize), String> {
        self.index(sh, false).await?;
        let partners = self.partners.lock().unwrap().clone();
        let mut up = 0;
        for p in &partners {
            let Some(addr) = self.addr(sh, p).await else {
                continue;
            };
            let req = s3m_protocol::exchange::Request {
                credential: None,
                body: s3m_protocol::exchange::Body::Probe { nonce: vec![0; 16] },
            };
            let r = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                sh.session.client().request(addr, req),
            )
            .await;
            if matches!(r, Ok(Ok(_))) {
                up += 1;
            } else {
                self.addrs.lock().unwrap().remove(&p.node_id);
            }
        }
        Ok((up, partners.len()))
    }

    /// Adresses des partenaires du dernier catalogue relu (déclarées par le
    /// Nœud) : points d'entrée de l'annuaire quand le Nœud est hors ligne.
    pub fn partner_addrs(&self) -> Vec<Multiaddr> {
        self.partners
            .lock()
            .unwrap()
            .iter()
            .filter_map(desc_addr)
            .collect()
    }

    /// Adresse d'un partenaire : son entrée DHT Node, sinon le catalogue.
    async fn addr(&self, sh: &Shared, p: &PartnerDesc) -> Option<Multiaddr> {
        if let Some(a) = self.addrs.lock().unwrap().get(&p.node_id) {
            return Some(a.clone());
        }
        let mut a = None;
        if let Some(dht) = sh.dht.get() {
            if let Some(env) = dht.get(p.node_id.to_vec()).await.ok().flatten() {
                a = crate::daemon::node_candidates(&p.node_id, &env)
                    .into_iter()
                    .next();
            }
        }
        if a.is_none() {
            a = desc_addr(p);
        }
        let a = a?;
        self.addrs.lock().unwrap().insert(p.node_id, a.clone());
        Some(a)
    }

    /// k blocs de données d'un stripe, depuis la parité (hash vérifié).
    async fn data(
        &self,
        sh: &Shared,
        s: &StripeDesc,
        table: &[PartnerDesc],
    ) -> Result<Vec<Vec<u8>>, String> {
        let k = s.k as usize;
        let mut shards: Vec<Option<Vec<u8>>> = vec![None; k * (1 + COEF)];
        let mut have = 0;
        for b in &s.blocks {
            if (b.index as usize) < k && b.is_padding {
                shards[b.index as usize] = Some(padding_block());
                have += 1;
            }
        }
        let keeper = sh.keeper.lock().await;
        if keeper.grant.is_none() {
            return Err("pas d'autorisation de secours (jamais obtenue du Nœud)".into());
        }
        for b in s.blocks.iter().filter(|b| b.index as usize >= k) {
            if have >= k {
                break;
            }
            let Some(p) = table.iter().find(|p| p.partner_id == b.partner_id) else {
                continue;
            };
            let Some(addr) = self.addr(sh, p).await else {
                continue;
            };
            let fetched = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                keeper.fetch_fragment(sh.session.client(), addr, &b.hash),
            )
            .await;
            if let Ok(Ok(d)) = fetched {
                if hash_sha256(&d) == b.hash && (b.index as usize) < shards.len() {
                    shards[b.index as usize] = Some(d);
                    have += 1;
                }
            } else {
                // Adresse peut-être périmée : relue au prochain essai.
                self.addrs.lock().unwrap().remove(&p.node_id);
            }
        }
        drop(keeper);
        if have < k {
            return Err(format!(
                "{have} fragment(s) sur {k} joignables chez les partenaires"
            ));
        }
        reconstruct_data(shards, k, COEF).map_err(|e| e.to_string())
    }
}
