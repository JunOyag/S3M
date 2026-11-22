//! Repli de la géolocalisation sur le pays (registres Internet régionaux).

use std::net::IpAddr;

use s3m_node::rir::{centroid, Countries};

const SAMPLE: &str = "2|ripencc|20261122|3|19830101|20261121|+0100
ripencc|*|ipv4|*|2|summary
ripencc|FR|ipv4|82.64.0.0|1048576|20060503|allocated|abc
ripencc|DE|ipv4|5.1.0.0|65536|20120101|assigned|def
ripencc|FR|ipv6|2a01:e00::|26|20070130|allocated|abc
ripencc|NL|ipv4|5.2.0.0|65536|20120101|available
arin|US|ipv4|8.8.8.0|256|19920101|allocated|ghi
";

#[test]
fn country_is_found_from_registry_ranges() {
    let c = Countries::parse(SAMPLE);
    let at = |s: &str| c.country(&s.parse::<IpAddr>().unwrap());
    assert_eq!(at("82.66.1.2").as_deref(), Some("FR"));
    assert_eq!(at("82.79.255.255").as_deref(), Some("FR"));
    assert_eq!(at("82.80.0.0"), None, "après la plage");
    assert_eq!(at("5.1.200.1").as_deref(), Some("DE"));
    assert_eq!(at("5.2.0.1"), None, "plage non attribuée ignorée");
    assert_eq!(at("8.8.8.8").as_deref(), Some("US"));
    assert_eq!(at("2a01:e0a:1::1").as_deref(), Some("FR"));
    let (lat, lon) = centroid("FR").unwrap();
    assert!((40.0..52.0).contains(&lat) && (-5.0..9.0).contains(&lon));
    assert!(centroid("ZZ").is_none());
}

/// Sans base DB-IP, la carte place l'adresse au centre de son pays.
#[test]
fn map_falls_back_to_the_country_without_dbip() {
    let dir = std::env::temp_dir().join(format!("p2p-rir-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let g = s3m_node::geo::Geo::open_dir(&dir);
    assert!(!g.available());
    Countries::parse(SAMPLE).save(&dir).unwrap();
    let g = s3m_node::geo::Geo::open_dir(&dir);
    assert!(g.available() && g.mode().starts_with("pays"));
    let p = g.locate("82.66.1.2").unwrap();
    assert_eq!((p.country.as_str(), p.city.as_str()), ("FR", ""));
    assert_eq!(Some((p.lat, p.lon)), centroid("FR"));
    assert!(g.locate("192.168.1.1").is_none(), "adresse privée");
    let _ = std::fs::remove_dir_all(&dir);
}
