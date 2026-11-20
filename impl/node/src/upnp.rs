//! Ouverture du port sur la box (UPnP IGD) — id `network.traversee-nat`.
//!
//! La recherche SSDP part de l'adresse locale de la route par défaut : sous
//! Windows, une recherche liée à `0.0.0.0` sort souvent par une carte
//! virtuelle (WSL, Hyper-V, VPN) et la box ne la voit jamais. Redirections
//! TCP et UDP (QUIC) du port d'écoute, renouvelées ; l'adresse externe est
//! remise à la pile réseau.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use igd_next::aio::tokio::search_gateway;
use igd_next::{PortMappingProtocol, SearchOptions};
use libp2p::multiaddr::Protocol;
use libp2p::Multiaddr;
use tokio::sync::mpsc;

use crate::net::NatState;

/// Durée de bail demandée (s) ; renouvellement à mi-bail.
const LEASE_S: u32 = 3600;
/// Nouvel essai si la box est introuvable.
const RETRY: Duration = Duration::from_secs(300);

/// Adresse IPv4 locale de la route par défaut (aucun paquet envoyé).
pub fn lan_ipv4() -> Option<Ipv4Addr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?;
    match s.local_addr().ok()?.ip() {
        IpAddr::V4(v) if !v.is_loopback() && !v.is_unspecified() => Some(v),
        _ => None,
    }
}

fn is_private(ip: Ipv4Addr) -> bool {
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 64
}

/// Adresses externes ouvertes sur la box.
pub fn external_addrs(ext: Ipv4Addr, port: u16) -> Vec<Multiaddr> {
    vec![
        Multiaddr::empty()
            .with(Protocol::Ip4(ext))
            .with(Protocol::Tcp(port)),
        Multiaddr::empty()
            .with(Protocol::Ip4(ext))
            .with(Protocol::Udp(port))
            .with(Protocol::QuicV1),
    ]
}

/// Tâche UPnP pour les ports `ports` ; état dans `nat`, adresses externes
/// envoyées sur `tx`.
pub fn spawn(ports: Vec<u16>, nat: Arc<Mutex<NatState>>, tx: mpsc::Sender<Multiaddr>) {
    if ports.is_empty() {
        nat.lock().unwrap().upnp = "désactivé (port d'écoute choisi au hasard)".into();
        return;
    }
    tokio::spawn(async move {
        loop {
            let set = |s: String| nat.lock().unwrap().upnp = s;
            let Some(lan) = lan_ipv4() else {
                set("aucune adresse locale (réseau absent ?)".into());
                tokio::time::sleep(RETRY).await;
                continue;
            };
            let opts = SearchOptions {
                bind_addr: SocketAddr::new(IpAddr::V4(lan), 0),
                timeout: Some(Duration::from_secs(5)),
                ..Default::default()
            };
            let gw = match search_gateway(opts).await {
                Ok(g) => g,
                Err(_) => {
                    set(format!(
                        "aucune box UPnP trouvée depuis {lan} (UPnP désactivé sur la box ?)"
                    ));
                    tokio::time::sleep(RETRY).await;
                    continue;
                }
            };
            let ext = match gw.get_external_ip().await {
                Ok(IpAddr::V4(v)) => v,
                Ok(other) => {
                    set(format!("box trouvée, adresse externe non IPv4 ({other})"));
                    tokio::time::sleep(RETRY).await;
                    continue;
                }
                Err(e) => {
                    set(format!(
                        "box trouvée ({}), adresse externe inconnue : {e}",
                        gw.addr
                    ));
                    tokio::time::sleep(RETRY).await;
                    continue;
                }
            };
            if is_private(ext) {
                set(format!(
                    "box non exposée à Internet (adresse {ext} : double NAT ?)"
                ));
                tokio::time::sleep(RETRY).await;
                continue;
            }
            let mut errors = Vec::new();
            for &port in &ports {
                for proto in [PortMappingProtocol::TCP, PortMappingProtocol::UDP] {
                    let local = SocketAddr::V4(SocketAddrV4::new(lan, port));
                    if let Err(e) = gw.add_port(proto, port, local, LEASE_S, "s3m-node").await {
                        errors.push(format!("{proto:?} {port} : {e}"));
                    }
                }
            }
            if errors.is_empty() {
                set(format!(
                    "port ouvert : {ext}:{} (box {})",
                    ports
                        .iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                    gw.addr
                ));
                for &port in &ports {
                    for a in external_addrs(ext, port) {
                        let _ = tx.send(a).await;
                    }
                }
                tokio::time::sleep(Duration::from_secs(LEASE_S as u64 / 2)).await;
            } else {
                set(format!(
                    "box trouvée, ouverture refusée : {}",
                    errors.join(" ; ")
                ));
                tokio::time::sleep(RETRY).await;
            }
        }
    });
}
