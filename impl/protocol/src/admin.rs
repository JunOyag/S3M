//! Canal d'administration du Nœud — id `deploiement.appairage-admin`.
//! Réf. spec : docs/07-deploiement/appairage-admin.md § Canal,
//! § Appairage. Messages JSON (une clé par message) et confirmation de
//! l'appairage SPAKE2, partagés par le Nœud (serveur) et le Connecteur
//! (client).

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use spake2::{Ed25519Group, Identity, Password, Spake2};

/// Protocole libp2p du canal.
pub const PROTOCOL: &str = "/s3m/admin/1";
/// Version annoncée par `hello`.
pub const VERSION: u32 = 1;
/// Identité SPAKE2 de l'appairage.
pub const PAIRING_IDENTITY: &[u8] = b"s3m/pairing/v1";
/// Port d'administration par défaut.
pub const DEFAULT_PORT: u16 = 4003;
/// Mode `setup` : identité temporaire.
pub const MODE_SETUP: &str = "setup";
/// Mode `node` : identité définitive.
pub const MODE_NODE: &str = "node";
/// Nœud démarré verrouillé (phrase de passe du coffre local attendue),
/// sous sa clé de déverrouillage (`deploiement.packaging#coffre-local`).
pub const MODE_LOCKED: &str = "locked";

/// Requête du canal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminRequest {
    Hello {},
    PakeStart {
        msg: String,
    },
    PakeConfirm {
        mac: String,
    },
    Login {
        totp: String,
    },
    /// Déverrouille un Nœud démarré verrouillé (mode `locked`).
    Unlock {
        passphrase: String,
    },
    Call {
        token: String,
        op: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(default)]
        body: Value,
    },
}

/// Réponse du canal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminResponse {
    Hello {
        mode: String,
        version: u32,
        /// `PeerId` de déverrouillage à distance, à retenir par le client
        /// (Nœud dont la phrase est gardée sous phrase de passe).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        unlock: Option<String>,
    },
    PakeReply {
        msg: String,
    },
    Session {
        token: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mac: Option<String>,
    },
    Result(Value),
    Error(String),
}

/// Code d'appairage `XXXX-XXXX` (base32, 40 bits) depuis 5 octets aléatoires.
pub fn pairing_code(random: [u8; 5]) -> String {
    let c = s3m_core::identity_derivation::base32_encode(&random);
    format!("{}-{}", &c[..4], &c[4..])
}

/// Code saisi : majuscules, sans tiret ni espace.
pub fn normalize_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_uppercase()
}

/// Début d'échange SPAKE2 : état et message à envoyer.
pub fn pake_start(code: &str) -> (Spake2<Ed25519Group>, Vec<u8>) {
    Spake2::<Ed25519Group>::start_symmetric(
        &Password::new(normalize_code(code).as_bytes()),
        &Identity::new(PAIRING_IDENTITY),
    )
}

/// Fin d'échange : clé `K`.
pub fn pake_finish(state: Spake2<Ed25519Group>, peer_msg: &[u8]) -> Result<Vec<u8>, String> {
    state
        .finish(peer_msg)
        .map_err(|e| format!("appairage : {e:?}"))
}

/// Côté de la confirmation.
#[derive(Debug, Clone, Copy)]
pub enum Side {
    Client,
    Node,
}

/// `HMAC-SHA256(K, côté ‖ PeerId_Nœud ‖ PeerId_client)`.
pub fn confirm_mac(k: &[u8], side: Side, node_peer: &[u8], client_peer: &[u8]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(k).expect("toute longueur");
    m.update(match side {
        Side::Client => b"client".as_slice(),
        Side::Node => b"node".as_slice(),
    });
    m.update(node_peer);
    m.update(client_peer);
    m.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_have_one_key_each() {
        let r = serde_json::to_value(AdminRequest::Hello {}).unwrap();
        assert_eq!(r, serde_json::json!({ "hello": {} }));
        let r = serde_json::to_value(AdminResponse::Result(serde_json::json!(1))).unwrap();
        assert_eq!(r, serde_json::json!({ "result": 1 }));
        let back: AdminRequest =
            serde_json::from_value(serde_json::json!({ "call": { "token": "t", "op": "status" } }))
                .unwrap();
        assert!(matches!(back, AdminRequest::Call { name: None, .. }));
    }

    #[test]
    fn same_code_gives_same_key_and_wrong_code_does_not() {
        let (a, ma) = pake_start("abcd-efgh");
        let (b, mb) = pake_start("ABCDEFGH");
        let (ka, kb) = (pake_finish(a, &mb).unwrap(), pake_finish(b, &ma).unwrap());
        assert_eq!(ka, kb);
        let (c, mc) = pake_start("ABCDEFGH");
        let (d, md) = pake_start("ABCDEFGX");
        assert_ne!(pake_finish(c, &md).unwrap(), pake_finish(d, &mc).unwrap());
        // Confirmation liée au côté et aux pairs.
        let n = confirm_mac(&ka, Side::Node, b"n", b"c");
        assert_ne!(n, confirm_mac(&ka, Side::Client, b"n", b"c"));
        assert_ne!(n, confirm_mac(&ka, Side::Node, b"n", b"x"));
        assert_eq!(pairing_code([0; 5]), "AAAA-AAAA");
    }
}
