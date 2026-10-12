//! Registre des étiquettes de `crypto.symmetric-suite` (Phase 0) — source
//! unique des chaînes du protocole. Réf. spec :
//! docs/03-crypto/symmetric-suite.md, sections « Registre des étiquettes
//! KDF » et « Contextes d'AAD ».
//!
//! Ce module ne contient QUE les étiquettes publiées par la page, jamais
//! improvisées. Deux registres distincts — mêmes règles d'unicité et
//! d'immuabilité, mais rôles différents :
//!
//! 1. **Étiquettes `info` (HKDF-SHA256)** : qualifient une *dérivation* de
//!    clé. Une étiquette n'apparaît qu'une fois dans le registre, quel que
//!    soit le secret d'entrée ou le KDF employé.
//! 2. **Contextes d'AAD** : qualifient un *chiffré* (ils entrent dans
//!    l'AAD d'un chiffrement, jamais dans une dérivation).
//!
//! Une étiquette publiée n'est jamais détournée ni réutilisée ; toute
//! révision est une nouvelle étiquette versionnée (`…/vN`), donc une
//! nouvelle version de protocole. Unicité testée par `tests/labels.rs`.
//!
//! Rappel d'usage : une étiquette unique passée en `info` est concaténée
//! **brute** — une seule composante, aucune frontière à délimiter (la page
//! n'écrit « encodage canonique » que pour les entrées multiples, voir
//! `symmetric_suite::canonical_encode`).

/// Exception `K_attach` — seul `info` vide du registre : réservé au secret
/// DH X25519 brut en v1 (et à lui seul — les variantes post-quantiques de
/// la même dérivation recevront une étiquette versionnée portant
/// l'identifiant d'algorithme, à trancher à leur passe).
pub const INFO_K_ATTACH_V1: &str = "";

/// `sig_priv_dispersal` — crypto.k-attach.
pub const DISPERSAL_SIGNING: &str = "dispersal-signing";
/// `K_dispersal_content` — crypto.k-dispersal.
pub const DISPERSAL_CONTENT: &str = "dispersal-content";
/// `K_dispersal_block` — crypto.k-dispersal.
pub const DISPERSAL_BLOCK: &str = "dispersal-block";
/// `K_self` (récupération depuis la seed utilisateur) — crypto.k-self.
pub const ATTACHMENT_RECOVERY: &str = "attachment-recovery";
/// `K_node_self` (récupération de l'identité Nœud) — crypto.k-node-self.
pub const NODE_RECOVERY: &str = "node-recovery";
/// `K_emergency_content` — protocols.espace-secours.
pub const EMERGENCY_CONTENT: &str = "emergency-content";
/// `sig_priv_emergency` — protocols.espace-secours.
pub const EMERGENCY_SIGNING: &str = "emergency-signing";
/// `user_dht_key` — network.dht-directory.
pub const DHT_LOOKUP: &str = "dht-lookup";
/// `sig_priv_user` — network.dht-directory.
pub const DHT_SIGNING: &str = "dht-signing";
/// `K_block` (sel `encryption_salt` nommé par crypto.k-block) — crypto.k-block.
pub const P2P_STORAGE_BLOCK_V1: &str = "p2p-storage/block/v1";
/// `K_nonce` (nonce synthétique) — cette page (crypto.symmetric-suite).
pub const P2P_STORAGE_SYNTHETIC_NONCE_V1: &str = "p2p-storage/synthetic-nonce/v1";
/// `K_wrap` (wrap de `master_key[version]`) — cette page
/// (crypto.symmetric-suite).
pub const P2P_STORAGE_MASTER_KEY_WRAP_V1: &str = "p2p-storage/master-key-wrap/v1";

/// Les 13 étiquettes `info` du registre (dont l'exception `info` vide) —
/// source du test d'unicité globale `tests/labels.rs`.
pub const ALL_INFO_LABELS: [&str; 13] = [
    INFO_K_ATTACH_V1,
    DISPERSAL_SIGNING,
    DISPERSAL_CONTENT,
    DISPERSAL_BLOCK,
    ATTACHMENT_RECOVERY,
    NODE_RECOVERY,
    EMERGENCY_CONTENT,
    EMERGENCY_SIGNING,
    DHT_LOOKUP,
    DHT_SIGNING,
    P2P_STORAGE_BLOCK_V1,
    P2P_STORAGE_SYNTHETIC_NONCE_V1,
    P2P_STORAGE_MASTER_KEY_WRAP_V1,
];

/// Contexte AAD du wrap de `master_key` (`wrapped_key` sous `K_wrap`) — le
/// contexte est suivi de `u16(version_wrappée) ‖ u16(version_courante)`.
pub const AAD_CONTEXT_MASTER_KEY_WRAP: &str = "master-key-wrap";
/// Contexte AAD des blocs (`K_block`, `K_dispersal_block`) — aucun champ
/// spécifique après le contexte (chiffrement déterministe : deux écritures
/// identiques → même AAD → même chiffré).
pub const AAD_CONTEXT_BLOCK: &str = "block";

/// Contextes d'AAD du registre distinct (la ligne « contextes par clé »
/// reste ouverte : chaque page de clé y liste les siens — ceux de cette
/// page sont les deux ci-dessus). Test d'unicité : `tests/labels.rs`.
pub const ALL_AAD_CONTEXTS: [&str; 2] = [AAD_CONTEXT_MASTER_KEY_WRAP, AAD_CONTEXT_BLOCK];
