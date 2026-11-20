//! Serveur du canal d'administration — id `deploiement.appairage-admin`.
//! Réf. spec : docs/07-deploiement/appairage-admin.md. Mode temporaire :
//! appairage SPAKE2 par code ; mode définitif : TOTP (RFC 6238). Les
//! opérations `status` et `action` sont celles du dashboard local.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures::StreamExt;
use hmac::{Hmac, Mac};
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{identity, mdns, noise, tcp, yamux, Multiaddr, PeerId, StreamProtocol};
use s3m_protocol::admin::{
    confirm_mac, pake_finish, pake_start, AdminRequest, AdminResponse, Side, MODE_NODE, MODE_SETUP,
    PROTOCOL, VERSION,
};
use sha1::Sha1;

use crate::local_http::{ActionFn, StatusFn};

/// Pas TOTP (s).
pub const TOTP_STEP: u64 = 30;
/// Expiration d'une session inactive.
pub const SESSION_IDLE: Duration = Duration::from_secs(30 * 60);
/// Échecs tolérés avant blocage.
pub const MAX_FAILURES: u32 = 5;
/// Actions réservées au dashboard local.
pub const LOCAL_ONLY: &[&str] = &["show_totp", "regenerate_totp"];

/// HOTP (RFC 4226) sur HMAC-SHA1, `digits` chiffres.
pub fn hotp(secret: &[u8], counter: u64, digits: u32) -> u32 {
    let mut m = <Hmac<Sha1> as Mac>::new_from_slice(secret).expect("toute longueur");
    m.update(&counter.to_be_bytes());
    let h = m.finalize().into_bytes();
    let o = (h[19] & 0x0f) as usize;
    let v = u32::from_be_bytes([h[o] & 0x7f, h[o + 1], h[o + 2], h[o + 3]]);
    v % 10u32.pow(digits)
}

/// URI d'enrôlement (`otpauth://`) du secret TOTP.
pub fn otpauth_uri(secret: &[u8], node_id: &[u8; 32]) -> String {
    format!(
        "otpauth://totp/S3m:{}?secret={}&issuer=S3m&algorithm=SHA1&digits=6&period={TOTP_STEP}",
        &hex::encode(node_id)[..8],
        s3m_core::identity_derivation::base32_encode(secret)
    )
}

/// QR code SVG d'un texte (correction d'erreur M).
pub fn qr_svg(text: &str) -> String {
    match qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::M) {
        Ok(c) => c
            .render::<qrcode::render::svg::Color>()
            .min_dimensions(220, 220)
            .quiet_zone(true)
            .build(),
        Err(_) => String::new(),
    }
}

fn now_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Secret TOTP courant (`None` : administration à distance impossible).
pub type SecretFn = Arc<dyn Fn() -> Option<[u8; 20]> + Send + Sync>;

/// Mode du serveur.
#[derive(Clone)]
pub enum Mode {
    /// Identité temporaire : appairage par code.
    Setup { code: String },
    /// Identité définitive : TOTP.
    Node { secret: SecretFn },
}

struct Session {
    peer: PeerId,
    last: Instant,
    /// Secret TOTP en vigueur à l'ouverture (changement de série : fermée).
    secret: Option<[u8; 20]>,
}

/// Règles d'authentification, indépendantes du transport (testables).
pub struct Auth {
    mode: Mode,
    node_peer: PeerId,
    pakes: HashMap<PeerId, Vec<u8>>,
    sessions: HashMap<String, Session>,
    failures: u32,
    locked_until: Option<Instant>,
    last_step: u64,
}

impl Auth {
    pub fn new(mode: Mode, node_peer: PeerId) -> Self {
        Self {
            mode,
            node_peer,
            pakes: HashMap::new(),
            sessions: HashMap::new(),
            failures: 0,
            locked_until: None,
            last_step: 0,
        }
    }

    fn locked(&self, now: Instant) -> bool {
        self.locked_until.is_some_and(|t| now < t)
    }

    fn fail(&mut self, now: Instant) -> AdminResponse {
        self.failures += 1;
        if self.failures >= MAX_FAILURES {
            let n = (self.failures - MAX_FAILURES).min(6);
            let d = Duration::from_secs((60u64 << n).min(3600));
            self.locked_until = Some(now + d);
        }
        AdminResponse::Error("authentification refusée".into())
    }

    fn open(&mut self, peer: PeerId, secret: Option<[u8; 20]>, now: Instant) -> String {
        self.failures = 0;
        self.locked_until = None;
        let mut t = [0u8; 32];
        getrandom::getrandom(&mut t).expect("aléa système");
        let token = hex::encode(t);
        self.sessions.insert(
            token.clone(),
            Session {
                peer,
                last: now,
                secret,
            },
        );
        token
    }

    fn current_secret(&self) -> Option<[u8; 20]> {
        match &self.mode {
            Mode::Node { secret } => secret(),
            Mode::Setup { .. } => None,
        }
    }

    /// Traite une requête de `peer` ; `unix` = heure courante (TOTP).
    pub fn handle(
        &mut self,
        peer: PeerId,
        req: AdminRequest,
        now: Instant,
        unix: u64,
        status: &StatusFn,
        action: &ActionFn,
    ) -> AdminResponse {
        let setup = matches!(self.mode, Mode::Setup { .. });
        match req {
            AdminRequest::Hello {} => AdminResponse::Hello {
                mode: if setup { MODE_SETUP } else { MODE_NODE }.into(),
                version: VERSION,
            },
            AdminRequest::PakeStart { msg } => {
                let Mode::Setup { code } = &self.mode else {
                    return AdminResponse::Error("Nœud déjà configuré : code 2FA attendu".into());
                };
                if self.locked(now) {
                    return AdminResponse::Error("trop d'essais : réessayez plus tard".into());
                }
                let Ok(msg) = hex::decode(msg) else {
                    return AdminResponse::Error("message invalide".into());
                };
                let (state, mine) = pake_start(code);
                match pake_finish(state, &msg) {
                    Ok(k) => {
                        self.pakes.insert(peer, k);
                        AdminResponse::PakeReply {
                            msg: hex::encode(mine),
                        }
                    }
                    Err(e) => AdminResponse::Error(e),
                }
            }
            AdminRequest::PakeConfirm { mac } => {
                if self.locked(now) {
                    return AdminResponse::Error("trop d'essais : réessayez plus tard".into());
                }
                let Some(k) = self.pakes.remove(&peer) else {
                    return AdminResponse::Error("appairage non commencé".into());
                };
                let (np, cp) = (self.node_peer.to_bytes(), peer.to_bytes());
                let want = confirm_mac(&k, Side::Client, &np, &cp);
                if hex::decode(mac).ok().as_deref() != Some(&want[..]) {
                    return self.fail(now);
                }
                let token = self.open(peer, None, now);
                AdminResponse::Session {
                    token,
                    mac: Some(hex::encode(confirm_mac(&k, Side::Node, &np, &cp))),
                }
            }
            AdminRequest::Login { totp } => {
                if setup {
                    return AdminResponse::Error(
                        "Nœud à configurer : code d'appairage attendu".into(),
                    );
                }
                if self.locked(now) {
                    return AdminResponse::Error("trop d'essais : réessayez plus tard".into());
                }
                let Some(secret) = self.current_secret() else {
                    return AdminResponse::Error("administration à distance indisponible".into());
                };
                let code: u32 = match totp.trim().parse() {
                    Ok(c) if totp.trim().len() == 6 => c,
                    _ => return self.fail(now),
                };
                let step = unix / TOTP_STEP;
                let ok = [step.wrapping_sub(1), step, step + 1]
                    .into_iter()
                    .find(|s| *s > self.last_step && hotp(&secret, *s, 6) == code);
                match ok {
                    Some(s) => {
                        self.last_step = s;
                        AdminResponse::Session {
                            token: self.open(peer, Some(secret), now),
                            mac: None,
                        }
                    }
                    None => self.fail(now),
                }
            }
            AdminRequest::Call {
                token,
                op,
                name,
                body,
            } => {
                let secret = self.current_secret();
                let valid = match self.sessions.get_mut(&token) {
                    Some(s)
                        if s.peer == peer
                            && now.duration_since(s.last) < SESSION_IDLE
                            && s.secret == secret =>
                    {
                        s.last = now;
                        true
                    }
                    _ => false,
                };
                if !valid {
                    // Session expirée de ce pair : oubliée ; jamais celle d'un autre.
                    if self.sessions.get(&token).is_some_and(|s| s.peer == peer) {
                        self.sessions.remove(&token);
                    }
                    return AdminResponse::Error("session expirée : reconnectez-vous".into());
                }
                match op.as_str() {
                    "status" => {
                        let mut v = status();
                        if let Some(o) = v.as_object_mut() {
                            o.remove("carte");
                        }
                        AdminResponse::Result(v)
                    }
                    "action" => {
                        let name = name.unwrap_or_default();
                        if !setup && LOCAL_ONLY.contains(&name.as_str()) {
                            return AdminResponse::Error(
                                "action réservée au tableau de bord local du Nœud".into(),
                            );
                        }
                        match action(&name, body) {
                            Ok(v) => AdminResponse::Result(v),
                            Err(e) => AdminResponse::Error(e),
                        }
                    }
                    _ => AdminResponse::Error(format!("opération inconnue : {op}")),
                }
            }
        }
    }
}

#[derive(NetworkBehaviour)]
struct AdminBehaviour {
    rr: request_response::json::Behaviour<AdminRequest, AdminResponse>,
    mdns: Toggle<mdns::tokio::Behaviour>,
}

/// Serveur en cours ; s'arrête par [`AdminServer::stop`] (ou à l'abandon).
pub struct AdminServer {
    task: tokio::task::JoinHandle<()>,
    pub listen: Arc<Mutex<Vec<Multiaddr>>>,
}

impl AdminServer {
    pub async fn stop(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

/// Démarre le canal sur `listen` avec l'identité `key` ; `announce` : annonce
/// mDNS (identité temporaire).
pub async fn serve(
    key: identity::Keypair,
    listen: &str,
    announce: bool,
    mode: Mode,
    status: StatusFn,
    action: ActionFn,
) -> Result<AdminServer, String> {
    let listen: Multiaddr = listen.parse().map_err(|e| format!("admin_listen : {e}"))?;
    let me = key.public().to_peer_id();
    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| e.to_string())?
        .with_behaviour(|k| {
            Ok(AdminBehaviour {
                rr: request_response::json::Behaviour::new(
                    [(StreamProtocol::new(PROTOCOL), ProtocolSupport::Inbound)],
                    request_response::Config::default(),
                ),
                mdns: Toggle::from(
                    announce
                        .then(|| {
                            mdns::tokio::Behaviour::new(
                                mdns::Config::default(),
                                k.public().to_peer_id(),
                            )
                            .ok()
                        })
                        .flatten(),
                ),
            })
        })
        .map_err(|e| e.to_string())?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    swarm.listen_on(listen).map_err(|e| e.to_string())?;
    let addrs = Arc::new(Mutex::new(Vec::new()));
    let a2 = addrs.clone();
    let mut auth = Auth::new(mode, me);
    let task = tokio::spawn(async move {
        loop {
            match swarm.select_next_some().await {
                SwarmEvent::NewListenAddr { address, .. } => a2.lock().unwrap().push(address),
                SwarmEvent::Behaviour(AdminBehaviourEvent::Rr(
                    request_response::Event::Message {
                        peer,
                        message:
                            request_response::Message::Request {
                                request, channel, ..
                            },
                    },
                )) => {
                    let resp =
                        auth.handle(peer, request, Instant::now(), now_s(), &status, &action);
                    let _ = swarm.behaviour_mut().rr.send_response(channel, resp);
                }
                _ => {}
            }
        }
    });
    // Laisse le temps d'ouvrir l'écoute (erreur de port signalée tôt).
    for _ in 0..20 {
        if !addrs.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok(AdminServer {
        task,
        listen: addrs,
    })
}
