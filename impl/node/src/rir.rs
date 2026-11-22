//! Repli de la géolocalisation (carte du dashboard) quand la base DB-IP
//! n'est pas téléchargeable : pays d'une adresse d'après les données
//! publiques des cinq registres Internet régionaux (AFRINIC, APNIC, ARIN,
//! LACNIC, RIPE NCC), placé au centre approximatif du pays. Lecture locale ;
//! aucune adresse n'est envoyée à un tiers.

use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// Fichier compact des plages, dans le répertoire de données.
pub const RIR_FILE: &str = "rir-country.bin";
/// Mention de la source.
pub const RIR_SOURCE: &str =
    "Pays seulement : données publiques des registres Internet régionaux (AFRINIC, APNIC, ARIN, LACNIC, RIPE NCC)";

const URLS: &[&str] = &[
    "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
    "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
    "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
    "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
];
const MAGIC: &[u8; 8] = b"S3MRIR01";

/// Plages d'adresses par pays, triées.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Countries {
    v4: Vec<(u32, u32, [u8; 2])>,
    v6: Vec<(u128, u128, [u8; 2])>,
}

impl Countries {
    /// Lit les lignes `registre|pays|ipv4|début|nombre|…` et
    /// `registre|pays|ipv6|début|longueur|…` (attribuées ou assignées).
    pub fn parse(text: &str) -> Self {
        let mut c = Countries::default();
        for line in text.lines() {
            let f: Vec<&str> = line.split('|').collect();
            if f.len() < 7 || f[0].starts_with('#') {
                continue;
            }
            if !matches!(f[6], "allocated" | "assigned") {
                continue;
            }
            let cc = f[1].as_bytes();
            if cc.len() != 2 || !cc.iter().all(u8::is_ascii_alphabetic) {
                continue;
            }
            let cc = [cc[0].to_ascii_uppercase(), cc[1].to_ascii_uppercase()];
            match f[2] {
                "ipv4" => {
                    let (Ok(start), Ok(n)) =
                        (f[3].parse::<std::net::Ipv4Addr>(), f[4].parse::<u64>())
                    else {
                        continue;
                    };
                    let s = u32::from(start) as u64;
                    if n == 0 || s + n - 1 > u32::MAX as u64 {
                        continue;
                    }
                    c.v4.push((s as u32, (s + n - 1) as u32, cc));
                }
                "ipv6" => {
                    let (Ok(start), Ok(len)) =
                        (f[3].parse::<std::net::Ipv6Addr>(), f[4].parse::<u32>())
                    else {
                        continue;
                    };
                    if len > 128 {
                        continue;
                    }
                    let s = u128::from(start);
                    let span = if len == 0 {
                        u128::MAX
                    } else {
                        (1u128 << (128 - len)) - 1
                    };
                    c.v6.push((s, s.saturating_add(span), cc));
                }
                _ => {}
            }
        }
        c.v4.sort();
        c.v6.sort();
        c
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    /// Code pays ISO 3166 d'une adresse.
    pub fn country(&self, ip: &IpAddr) -> Option<String> {
        let cc = match ip {
            IpAddr::V4(v) => find(&self.v4, u32::from(*v)),
            IpAddr::V6(v) => find(&self.v6, u128::from(*v)),
        }?;
        Some(String::from_utf8_lossy(&cc).into_owned())
    }

    fn encode(&self) -> Vec<u8> {
        let mut b = MAGIC.to_vec();
        b.extend((self.v4.len() as u32).to_le_bytes());
        b.extend((self.v6.len() as u32).to_le_bytes());
        for (s, e, c) in &self.v4 {
            b.extend(s.to_le_bytes());
            b.extend(e.to_le_bytes());
            b.extend(c);
        }
        for (s, e, c) in &self.v6 {
            b.extend(s.to_le_bytes());
            b.extend(e.to_le_bytes());
            b.extend(c);
        }
        b
    }

    fn decode(b: &[u8]) -> Option<Self> {
        if b.get(..8)? != MAGIC {
            return None;
        }
        let n4 = u32::from_le_bytes(b.get(8..12)?.try_into().ok()?) as usize;
        let n6 = u32::from_le_bytes(b.get(12..16)?.try_into().ok()?) as usize;
        let mut c = Countries::default();
        let mut o = 16;
        for _ in 0..n4 {
            let r = b.get(o..o + 10)?;
            c.v4.push((
                u32::from_le_bytes(r[0..4].try_into().ok()?),
                u32::from_le_bytes(r[4..8].try_into().ok()?),
                [r[8], r[9]],
            ));
            o += 10;
        }
        for _ in 0..n6 {
            let r = b.get(o..o + 34)?;
            c.v6.push((
                u128::from_le_bytes(r[0..16].try_into().ok()?),
                u128::from_le_bytes(r[16..32].try_into().ok()?),
                [r[32], r[33]],
            ));
            o += 34;
        }
        Some(c)
    }

    /// Enregistre les plages dans `dir` (écriture atomique).
    pub fn save(&self, dir: &Path) -> Result<PathBuf, String> {
        let path = dir.join(RIR_FILE);
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, self.encode()).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
        Ok(path)
    }

    /// Plages enregistrées dans `dir`, si présentes.
    pub fn open(dir: &Path) -> Option<Self> {
        Self::decode(&std::fs::read(dir.join(RIR_FILE)).ok()?)
    }
}

fn find<T: Ord + Copy>(ranges: &[(T, T, [u8; 2])], ip: T) -> Option<[u8; 2]> {
    let i = ranges.partition_point(|(s, _, _)| *s <= ip);
    let (s, e, c) = ranges.get(i.checked_sub(1)?)?;
    (*s <= ip && ip <= *e).then_some(*c)
}

/// Télécharge les données des cinq registres et enregistre les plages.
pub fn update(dir: &Path) -> Result<PathBuf, String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let mut text = String::new();
    let mut errors = Vec::new();
    for url in URLS {
        match ureq::get(url).call() {
            Ok(resp) => {
                let mut s = String::new();
                resp.into_reader()
                    .take(256 << 20)
                    .read_to_string(&mut s)
                    .map_err(|e| e.to_string())?;
                text.push_str(&s);
                text.push('\n');
            }
            Err(e) => errors.push(format!("{url} : {e}")),
        }
    }
    let c = Countries::parse(&text);
    if c.is_empty() {
        return Err(format!(
            "registres Internet injoignables : {}",
            errors.join(" ; ")
        ));
    }
    c.save(dir)
}

/// Centre approximatif d'un pays (ISO 3166 alpha-2), pour la carte.
pub fn centroid(cc: &str) -> Option<(f64, f64)> {
    CENTROIDS
        .iter()
        .find(|(c, _, _)| c.eq_ignore_ascii_case(cc))
        .map(|(_, lat, lon)| (*lat as f64, *lon as f64))
}

/// Centres approximatifs (degrés), précision de l'ordre du degré.
const CENTROIDS: &[(&str, f32, f32)] = &[
    ("AD", 42.5, 1.6),
    ("AE", 24.0, 54.0),
    ("AF", 33.9, 67.7),
    ("AG", 17.1, -61.8),
    ("AI", 18.2, -63.1),
    ("AL", 41.2, 20.2),
    ("AM", 40.1, 45.0),
    ("AO", -11.2, 17.9),
    ("AQ", -75.0, 0.0),
    ("AR", -38.4, -63.6),
    ("AS", -14.3, -170.7),
    ("AT", 47.5, 14.6),
    ("AU", -25.3, 133.8),
    ("AW", 12.5, -70.0),
    ("AX", 60.2, 20.0),
    ("AZ", 40.1, 47.6),
    ("BA", 43.9, 17.7),
    ("BB", 13.2, -59.5),
    ("BD", 23.7, 90.4),
    ("BE", 50.5, 4.5),
    ("BF", 12.2, -1.6),
    ("BG", 42.7, 25.5),
    ("BH", 26.0, 50.6),
    ("BI", -3.4, 29.9),
    ("BJ", 9.3, 2.3),
    ("BL", 17.9, -62.8),
    ("BM", 32.3, -64.8),
    ("BN", 4.5, 114.7),
    ("BO", -16.3, -63.6),
    ("BQ", 12.2, -68.3),
    ("BR", -14.2, -51.9),
    ("BS", 25.0, -77.4),
    ("BT", 27.5, 90.4),
    ("BW", -22.3, 24.7),
    ("BY", 53.7, 27.9),
    ("BZ", 17.2, -88.5),
    ("CA", 56.1, -106.3),
    ("CD", -4.0, 21.8),
    ("CF", 6.6, 20.9),
    ("CG", -0.2, 15.8),
    ("CH", 46.8, 8.2),
    ("CI", 7.5, -5.5),
    ("CK", -21.2, -159.8),
    ("CL", -35.7, -71.5),
    ("CM", 7.4, 12.4),
    ("CN", 35.9, 104.2),
    ("CO", 4.6, -74.3),
    ("CR", 9.7, -83.8),
    ("CU", 21.5, -77.8),
    ("CV", 16.0, -24.0),
    ("CW", 12.2, -69.0),
    ("CY", 35.1, 33.4),
    ("CZ", 49.8, 15.5),
    ("DE", 51.2, 10.5),
    ("DJ", 11.8, 42.6),
    ("DK", 56.3, 9.5),
    ("DM", 15.4, -61.4),
    ("DO", 18.7, -70.2),
    ("DZ", 28.0, 1.7),
    ("EC", -1.8, -78.2),
    ("EE", 58.6, 25.0),
    ("EG", 26.8, 30.8),
    ("ER", 15.2, 39.8),
    ("ES", 40.5, -3.7),
    ("ET", 9.1, 40.5),
    ("FI", 61.9, 25.7),
    ("FJ", -17.7, 178.1),
    ("FK", -51.8, -59.5),
    ("FM", 7.4, 150.6),
    ("FO", 61.9, -6.9),
    ("FR", 46.2, 2.2),
    ("GA", -0.8, 11.6),
    ("GB", 55.4, -3.4),
    ("GD", 12.1, -61.7),
    ("GE", 42.3, 43.4),
    ("GF", 3.9, -53.1),
    ("GG", 49.5, -2.6),
    ("GH", 7.9, -1.0),
    ("GI", 36.1, -5.4),
    ("GL", 71.7, -42.6),
    ("GM", 13.4, -15.3),
    ("GN", 9.9, -9.7),
    ("GP", 16.3, -61.6),
    ("GQ", 1.7, 10.3),
    ("GR", 39.1, 21.8),
    ("GT", 15.8, -90.2),
    ("GU", 13.4, 144.8),
    ("GW", 11.8, -15.2),
    ("GY", 4.9, -58.9),
    ("HK", 22.4, 114.1),
    ("HN", 15.2, -86.2),
    ("HR", 45.1, 15.2),
    ("HT", 19.0, -72.3),
    ("HU", 47.2, 19.5),
    ("ID", -0.8, 113.9),
    ("IE", 53.4, -8.2),
    ("IL", 31.0, 34.9),
    ("IM", 54.2, -4.5),
    ("IN", 20.6, 79.0),
    ("IO", -6.3, 71.9),
    ("IQ", 33.2, 43.7),
    ("IR", 32.4, 53.7),
    ("IS", 64.9, -19.0),
    ("IT", 41.9, 12.6),
    ("JE", 49.2, -2.1),
    ("JM", 18.1, -77.3),
    ("JO", 30.6, 36.2),
    ("JP", 36.2, 138.3),
    ("KE", 0.0, 37.9),
    ("KG", 41.2, 74.8),
    ("KH", 12.6, 105.0),
    ("KI", 1.9, -157.4),
    ("KM", -11.9, 43.9),
    ("KN", 17.4, -62.8),
    ("KP", 40.3, 127.5),
    ("KR", 35.9, 127.8),
    ("KW", 29.3, 47.5),
    ("KY", 19.3, -81.3),
    ("KZ", 48.0, 66.9),
    ("LA", 19.9, 102.5),
    ("LB", 33.9, 35.9),
    ("LC", 13.9, -61.0),
    ("LI", 47.2, 9.6),
    ("LK", 7.9, 80.8),
    ("LR", 6.4, -9.4),
    ("LS", -29.6, 28.2),
    ("LT", 55.2, 23.9),
    ("LU", 49.8, 6.1),
    ("LV", 56.9, 24.6),
    ("LY", 26.3, 17.2),
    ("MA", 31.8, -7.1),
    ("MC", 43.7, 7.4),
    ("MD", 47.4, 28.4),
    ("ME", 42.7, 19.4),
    ("MF", 18.1, -63.1),
    ("MG", -18.8, 46.9),
    ("MH", 7.1, 171.2),
    ("MK", 41.6, 21.7),
    ("ML", 17.6, -4.0),
    ("MM", 21.9, 96.0),
    ("MN", 46.9, 103.8),
    ("MO", 22.2, 113.5),
    ("MP", 15.1, 145.7),
    ("MQ", 14.6, -61.0),
    ("MR", 21.0, -10.9),
    ("MS", 16.7, -62.2),
    ("MT", 35.9, 14.4),
    ("MU", -20.3, 57.6),
    ("MV", 3.2, 73.2),
    ("MW", -13.3, 34.3),
    ("MX", 23.6, -102.6),
    ("MY", 4.2, 102.0),
    ("MZ", -18.7, 35.5),
    ("NA", -22.9, 18.5),
    ("NC", -20.9, 165.6),
    ("NE", 17.6, 8.1),
    ("NF", -29.0, 168.0),
    ("NG", 9.1, 8.7),
    ("NI", 12.9, -85.2),
    ("NL", 52.1, 5.3),
    ("NO", 60.5, 8.5),
    ("NP", 28.4, 84.1),
    ("NR", -0.5, 166.9),
    ("NU", -19.1, -169.9),
    ("NZ", -40.9, 174.9),
    ("OM", 21.5, 55.9),
    ("PA", 8.5, -80.8),
    ("PE", -9.2, -75.0),
    ("PF", -17.7, -149.4),
    ("PG", -6.3, 143.9),
    ("PH", 12.9, 121.8),
    ("PK", 30.4, 69.3),
    ("PL", 51.9, 19.1),
    ("PM", 46.9, -56.3),
    ("PR", 18.2, -66.6),
    ("PS", 31.9, 35.2),
    ("PT", 39.4, -8.2),
    ("PW", 7.5, 134.6),
    ("PY", -23.4, -58.4),
    ("QA", 25.4, 51.2),
    ("RE", -21.1, 55.5),
    ("RO", 45.9, 25.0),
    ("RS", 44.0, 21.0),
    ("RU", 61.5, 105.3),
    ("RW", -1.9, 29.9),
    ("SA", 23.9, 45.1),
    ("SB", -9.6, 160.2),
    ("SC", -4.7, 55.5),
    ("SD", 12.9, 30.2),
    ("SE", 60.1, 18.6),
    ("SG", 1.4, 103.8),
    ("SI", 46.2, 15.0),
    ("SK", 48.7, 19.7),
    ("SL", 8.5, -11.8),
    ("SM", 43.9, 12.5),
    ("SN", 14.5, -14.5),
    ("SO", 5.2, 46.2),
    ("SR", 3.9, -56.0),
    ("SS", 7.9, 30.0),
    ("ST", 0.2, 6.6),
    ("SV", 13.8, -88.9),
    ("SX", 18.0, -63.1),
    ("SY", 34.8, 39.0),
    ("SZ", -26.5, 31.5),
    ("TC", 21.7, -71.8),
    ("TD", 15.5, 18.7),
    ("TG", 8.6, 0.8),
    ("TH", 15.9, 101.0),
    ("TJ", 38.9, 71.3),
    ("TL", -8.9, 125.7),
    ("TM", 39.0, 59.6),
    ("TN", 33.9, 9.5),
    ("TO", -21.2, -175.2),
    ("TR", 39.0, 35.2),
    ("TT", 10.7, -61.2),
    ("TV", -7.1, 177.6),
    ("TW", 23.7, 121.0),
    ("TZ", -6.4, 34.9),
    ("UA", 48.4, 31.2),
    ("UG", 1.4, 32.3),
    ("US", 39.8, -98.6),
    ("UY", -32.5, -55.8),
    ("UZ", 41.4, 64.6),
    ("VA", 41.9, 12.5),
    ("VC", 13.3, -61.2),
    ("VE", 6.4, -66.6),
    ("VG", 18.4, -64.6),
    ("VI", 18.3, -64.9),
    ("VN", 14.1, 108.3),
    ("VU", -15.4, 166.9),
    ("WF", -13.8, -177.2),
    ("WS", -13.8, -172.1),
    ("XK", 42.6, 20.9),
    ("YE", 15.6, 48.5),
    ("YT", -12.8, 45.2),
    ("ZA", -30.6, 22.9),
    ("ZM", -13.1, 27.8),
    ("ZW", -19.0, 29.2),
    ("EU", 50.1, 9.0),
    ("AP", 15.0, 105.0),
];
