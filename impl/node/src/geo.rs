//! Géolocalisation locale des adresses IP pour la carte du dashboard —
//! id `deploiement.packaging` § Liste des partenaires et carte. Base au
//! format MMDB (DB-IP « City Lite », CC BY 4.0), lue localement ; aucune
//! requête vers un service extérieur. Téléchargement explicite par
//! l'opérateur : `p2p-storage-node geoip-update <répertoire>`.

use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// Mention exigée par la licence de la base.
pub const ATTRIBUTION: &str = "IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0";
/// Nom du fichier de base dans le répertoire de données.
pub const DB_FILE: &str = "dbip-city-lite.mmdb";

/// Position approximative.
#[derive(Debug, Clone, PartialEq)]
pub struct Place {
    pub lat: f64,
    pub lon: f64,
    pub country: String,
    pub city: String,
}

/// Base ouverte (ou absente).
pub struct Geo(Option<maxminddb::Reader<Vec<u8>>>);

impl Geo {
    pub fn open(path: &Path) -> Self {
        Self(maxminddb::Reader::open_readfile(path).ok())
    }

    pub fn none() -> Self {
        Self(None)
    }

    pub fn available(&self) -> bool {
        self.0.is_some()
    }

    /// Position d'une adresse ; `None` si privée, inconnue ou base absente.
    pub fn locate(&self, ip: &str) -> Option<Place> {
        let ip: IpAddr = ip.parse().ok()?;
        if is_private(&ip) {
            return None;
        }
        let r = self.0.as_ref()?;
        let c: maxminddb::geoip2::City = r.lookup(ip).ok()?;
        let loc = c.location?;
        let en = |n: Option<std::collections::BTreeMap<&str, &str>>| {
            n.and_then(|m| m.get("en").map(|s| s.to_string()))
                .unwrap_or_default()
        };
        Some(Place {
            lat: loc.latitude?,
            lon: loc.longitude?,
            country: c
                .country
                .map(|x| {
                    x.iso_code
                        .map(str::to_string)
                        .unwrap_or_else(|| en(x.names))
                })
                .unwrap_or_default(),
            city: c.city.map(|x| en(x.names)).unwrap_or_default(),
        })
    }
}

/// Adresse non routable sur Internet.
pub fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_unspecified()
                || v.octets()[0] == 100 && (v.octets()[1] & 0xC0) == 64
        }
        IpAddr::V6(v) => {
            v.is_loopback()
                || v.is_unspecified()
                || (v.segments()[0] & 0xfe00) == 0xfc00
                || (v.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// `(année, mois)` d'un instant Unix (calendrier grégorien).
pub fn year_month(unix_s: u64) -> (i64, u32) {
    let z = (unix_s / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    (y, m)
}

/// Télécharge la base du mois (ou du mois précédent) dans `dir`.
pub fn update(dir: &Path, now: u64) -> Result<PathBuf, String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let (y, m) = year_month(now);
    let prev = if m == 1 { (y - 1, 12) } else { (y, m - 1) };
    let mut last = String::new();
    for (y, m) in [(y, m), prev] {
        let url = format!("https://download.db-ip.com/free/dbip-city-lite-{y}-{m:02}.mmdb.gz");
        match ureq::get(&url).call() {
            Ok(resp) => {
                let mut gz = Vec::new();
                resp.into_reader()
                    .take(512 << 20)
                    .read_to_end(&mut gz)
                    .map_err(|e| e.to_string())?;
                let mut db = Vec::new();
                flate2::read::GzDecoder::new(&gz[..])
                    .read_to_end(&mut db)
                    .map_err(|e| format!("décompression : {e}"))?;
                maxminddb::Reader::from_source(db.clone())
                    .map_err(|e| format!("base invalide : {e}"))?;
                let path = dir.join(DB_FILE);
                let tmp = path.with_extension("tmp");
                std::fs::write(&tmp, db).map_err(|e| e.to_string())?;
                std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
                return Ok(path);
            }
            Err(e) => last = format!("{url} : {e}"),
        }
    }
    Err(last)
}
