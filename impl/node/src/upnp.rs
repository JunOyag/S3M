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
            let mut opened: Vec<(PortMappingProtocol, u16, u16)> = Vec::new();
            for &port in &ports {
                for proto in [PortMappingProtocol::TCP, PortMappingProtocol::UDP] {
                    match map_port(&gw, proto, port, lan).await {
                        Ok(ext_port) => opened.push((proto, port, ext_port)),
                        Err(e) => errors.push(format!("{proto:?} {port} : {e}")),
                    }
                }
            }
            if errors.is_empty() {
                let shown: Vec<String> = opened
                    .iter()
                    .map(|(proto, port, ext_port)| {
                        if port == ext_port {
                            format!("{proto:?} {port}")
                        } else {
                            format!("{proto:?} {port} (externe {ext_port}, le {port} est déjà pris sur la box)")
                        }
                    })
                    .collect();
                set(format!(
                    "port ouvert : {ext} — {} (box {})",
                    shown.join(", "),
                    gw.addr
                ));
                for (proto, _, ext_port) in &opened {
                    let a = Multiaddr::empty().with(Protocol::Ip4(ext));
                    let a = match proto {
                        PortMappingProtocol::TCP => a.with(Protocol::Tcp(*ext_port)),
                        PortMappingProtocol::UDP => {
                            a.with(Protocol::Udp(*ext_port)).with(Protocol::QuicV1)
                        }
                    };
                    let _ = tx.send(a).await;
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

/// Code d'erreur UPnP d'une réponse de la box (`<errorCode>718</errorCode>`).
fn upnp_code(e: &str) -> Option<u32> {
    let i = e.find("<errorCode>")? + "<errorCode>".len();
    e[i..].split('<').next()?.trim().parse().ok()
}

/// Message lisible d'une erreur de la box.
pub fn describe(e: &str) -> String {
    match upnp_code(e) {
        Some(718) => "port déjà redirigé vers une autre machine (718)".into(),
        Some(725) => "la box n'accepte que des redirections permanentes (725)".into(),
        Some(606) | Some(501) => "action refusée par la box (UPnP en lecture seule ?)".into(),
        Some(c) => format!("erreur UPnP {c}"),
        None => e.chars().take(120).collect(),
    }
}

/// Redirige `port` (même numéro externe si possible) vers `lan:port` ; rend
/// le port externe. Une redirection déjà en place vers cette machine est
/// reprise ; si le numéro est pris par une autre, la box en choisit un autre.
async fn map_port(
    gw: &igd_next::aio::Gateway<igd_next::aio::tokio::Tokio>,
    proto: PortMappingProtocol,
    port: u16,
    lan: Ipv4Addr,
) -> Result<u16, String> {
    let local = SocketAddr::V4(SocketAddrV4::new(lan, port));
    let first = match gw.add_port(proto, port, local, LEASE_S, "s3m-node").await {
        Ok(()) => return Ok(port),
        Err(e) => e.to_string(),
    };
    // Bail refusé (725) : redirection permanente.
    if upnp_code(&first) == Some(725)
        && gw.add_port(proto, port, local, 0, "s3m-node").await.is_ok()
    {
        return Ok(port);
    }
    for i in 0..256 {
        let Ok(m) = gw.get_generic_port_mapping_entry(i).await else {
            break;
        };
        if m.external_port == port && m.protocol == proto {
            if m.internal_client == lan.to_string() && m.internal_port == port {
                return Ok(port);
            }
            break;
        }
    }
    match gw.add_any_port(proto, local, LEASE_S, "s3m-node").await {
        Ok(p) => Ok(p),
        Err(e) => Err(format!(
            "{} ; autre port : {}",
            describe(&first),
            describe(&e.to_string())
        )),
    }
}
