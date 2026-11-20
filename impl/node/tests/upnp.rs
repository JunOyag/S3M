//! `network.traversee-nat` § UPnP : recherche de la box par l'interface du
//! réseau local. Essai réel, sans redirection : `cargo test --test upnp -- --ignored`.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use igd_next::aio::tokio::search_gateway;
use igd_next::SearchOptions;
use s3m_node::upnp::{external_addrs, lan_ipv4};

#[test]
fn local_address_and_external_addresses_are_well_formed() {
    if let Some(ip) = lan_ipv4() {
        assert!(!ip.is_loopback() && !ip.is_unspecified());
    }
    let a = external_addrs("203.0.113.7".parse().unwrap(), 4001);
    assert_eq!(a[0].to_string(), "/ip4/203.0.113.7/tcp/4001");
    assert_eq!(a[1].to_string(), "/ip4/203.0.113.7/udp/4001/quic-v1");
}

#[tokio::test]
#[ignore = "réseau réel : box UPnP requise"]
async fn the_box_is_found_from_the_lan_interface() {
    let lan = lan_ipv4().expect("adresse locale");
    let gw = search_gateway(SearchOptions {
        bind_addr: SocketAddr::new(IpAddr::V4(lan), 0),
        timeout: Some(Duration::from_secs(5)),
        ..Default::default()
    })
    .await
    .expect("box trouvée");
    let ext = gw.get_external_ip().await.expect("adresse externe");
    println!("box {} depuis {lan}, adresse externe {ext}", gw.addr);
}
