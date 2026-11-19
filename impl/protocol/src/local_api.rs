//! Protection de l'API locale des dashboards — id `deploiement.packaging`,
//! partie commune Nœud/Connecteur (Phase 6). Réf. spec :
//! docs/07-deploiement/packaging.md § API locale.
//!
//! - Liaison sur `127.0.0.1` uniquement.
//! - Jeton de 256 bits propre au démarrage, en-tête `Authorization: Bearer`,
//!   comparaison à temps constant ; jamais dans l'URL de requête.
//! - Remise au dashboard par **fragment d'URL** (`#…`).
//! - `Origin` présent ⇒ égal à l'origine du dashboard ; `Host` égal à
//!   l'adresse liée (rebond DNS).
//! - WebSocket : `Origin`/`Host` vérifiés à la poignée de main, jeton dans le
//!   premier message.

use std::net::SocketAddr;

/// Refus d'une requête de l'API locale.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ApiRejection {
    #[error("adresse de liaison autre que 127.0.0.1")]
    NotLoopback,
    #[error("jeton absent ou invalide")]
    BadToken,
    #[error("Origin non autorisée")]
    BadOrigin,
    #[error("Host non autorisé")]
    BadHost,
}

/// Comparaison à temps constant.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Garde de l'API locale d'un dashboard.
#[derive(Clone)]
pub struct LocalApiGuard {
    token_hex: String,
    port: u16,
}

impl LocalApiGuard {
    /// `token` : 32 octets aléatoires tirés à chaque démarrage ; `bound` :
    /// adresse effectivement liée (doit être `127.0.0.1`).
    pub fn new(token: [u8; 32], bound: SocketAddr) -> Result<Self, ApiRejection> {
        match bound {
            SocketAddr::V4(a) if a.ip().octets() == [127, 0, 0, 1] => Ok(Self {
                token_hex: hex(&token),
                port: a.port(),
            }),
            _ => Err(ApiRejection::NotLoopback),
        }
    }

    /// Origine du dashboard servi par le binaire.
    pub fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// URL d'ouverture du navigateur : jeton dans le fragment (jamais envoyé
    /// au serveur, ni journalisé, ni transmis dans `Referer`).
    pub fn dashboard_url(&self) -> String {
        format!("{}/#token={}", self.origin(), self.token_hex)
    }

    fn check_origin_host(
        &self,
        origin: Option<&str>,
        host: Option<&str>,
    ) -> Result<(), ApiRejection> {
        if origin.is_some_and(|o| o != self.origin()) {
            return Err(ApiRejection::BadOrigin);
        }
        if host != Some(&format!("127.0.0.1:{}", self.port)[..]) {
            return Err(ApiRejection::BadHost);
        }
        Ok(())
    }

    /// Requête HTTP : `Origin` (optionnel), `Host`, `Authorization`.
    pub fn check_http(
        &self,
        origin: Option<&str>,
        host: Option<&str>,
        authorization: Option<&str>,
    ) -> Result<(), ApiRejection> {
        self.check_origin_host(origin, host)?;
        let presented = authorization
            .and_then(|a| a.strip_prefix("Bearer "))
            .ok_or(ApiRejection::BadToken)?;
        if !ct_eq(presented.as_bytes(), self.token_hex.as_bytes()) {
            return Err(ApiRejection::BadToken);
        }
        Ok(())
    }

    /// Poignée de main WebSocket : `Origin` et `Host` seulement.
    pub fn check_ws_handshake(
        &self,
        origin: Option<&str>,
        host: Option<&str>,
    ) -> Result<(), ApiRejection> {
        self.check_origin_host(origin, host)
    }

    /// Premier message WebSocket : le jeton ; sinon la connexion est fermée.
    pub fn check_ws_first_message(&self, message: &str) -> Result<(), ApiRejection> {
        if ct_eq(message.trim().as_bytes(), self.token_hex.as_bytes()) {
            Ok(())
        } else {
            Err(ApiRejection::BadToken)
        }
    }
}
