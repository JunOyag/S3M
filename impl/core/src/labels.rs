//! Registre des étiquettes de `crypto.symmetric-suite` (Phase 0, spec V3) —
//! source unique des chaînes du protocole. Réf. spec :
//! docs/03-crypto/symmetric-suite.md, sections « KDF — HKDF-SHA256 »,
//! « Registre des étiquettes KDF » et « AAD ».
//!
//! Deux registres distincts, mêmes règles d'unicité et d'immuabilité :
//!
//! 1. **Étiquettes KDF** : le `label` de la convention
//!    `info = KDF_PREFIX ‖ L(label) ‖ L(entrées publiques…)` (voir
//!    `symmetric_suite::kdf`). Une étiquette n'apparaît qu'une fois.
//! 2. **Contextes d'AAD** : qualifient un *chiffré*, jamais une dérivation.
//!
//! Une révision de la convention change `KDF_PREFIX` (`…/kdf/v2`), donc la
//! version de protocole. Unicité testée par `tests/labels.rs`.

/// Préfixe brut, en tête de tout `info` HKDF du protocole.
pub const KDF_PREFIX: &str = "s3m/kdf/v1";

/// `K_attach` — crypto.k-attach.
pub const ATTACH: &str = "attach";
/// `sig_priv_dispersal` — crypto.k-attach.
pub const DISPERSAL_SIGNING: &str = "dispersal-signing";
/// `K_dispersal_content` — crypto.k-dispersal.
pub const DISPERSAL_CONTENT: &str = "dispersal-content";
/// `K_dispersal_block` — crypto.k-dispersal.
pub const DISPERSAL_BLOCK: &str = "dispersal-block";
/// `K_emergency_content` — protocols.espace-secours.
pub const EMERGENCY_CONTENT: &str = "emergency-content";
/// `sig_priv_emergency` — protocols.espace-secours.
pub const EMERGENCY_SIGNING: &str = "emergency-signing";
/// `K_self` — crypto.k-self.
pub const ATTACHMENT_RECOVERY: &str = "attachment-recovery";
/// `K_node_self` — crypto.k-node-self.
pub const NODE_RECOVERY: &str = "node-recovery";
/// `user_dht_key` — network.dht-directory.
pub const DHT_LOOKUP: &str = "dht-lookup";
/// graine de `sig_priv_user` — network.dht-directory.
pub const DHT_SIGNING: &str = "dht-signing";
/// `K_block` — crypto.k-block.
pub const BLOCK: &str = "block";
/// `K_wrap` — crypto.symmetric-suite.
pub const MASTER_KEY_WRAP: &str = "master-key-wrap";
/// Preuve d'authentification Connecteur → Nœud — protocols.echange-blocs.
pub const CONNECTOR_AUTH: &str = "connector-auth";
/// `K_node_snapshot` — deploiement.disaster-recovery § Snapshot.
pub const NODE_SNAPSHOT: &str = "node-snapshot";

/// Les 14 étiquettes KDF du registre — source du test d'unicité.
pub const ALL_KDF_LABELS: [&str; 14] = [
    ATTACH,
    DISPERSAL_SIGNING,
    DISPERSAL_CONTENT,
    DISPERSAL_BLOCK,
    EMERGENCY_CONTENT,
    EMERGENCY_SIGNING,
    ATTACHMENT_RECOVERY,
    NODE_RECOVERY,
    DHT_LOOKUP,
    DHT_SIGNING,
    BLOCK,
    MASTER_KEY_WRAP,
    CONNECTOR_AUTH,
    NODE_SNAPSHOT,
];

/// Étiquettes retirées en V3 — jamais réutilisables (test `tests/labels.rs`).
pub const RETIRED_LABELS: [&str; 3] = [
    "s3m/block/v1",
    "s3m/synthetic-nonce/v1",
    "s3m/master-key-wrap/v1",
];

/// Contexte AAD du wrap de `master_key` — suivi de
/// `u16(version_wrappée) ‖ u16(version_courante)`. (Les blocs n'ont pas de
/// contexte : leur AAD est l'en-tête de version seul.)
pub const AAD_CONTEXT_MASTER_KEY_WRAP: &str = "master-key-wrap";

/// Contextes d'AAD du registre distinct. Les libellés AAD des blobs DHT
/// (page network.dht-directory) y seront ajoutés par cette tâche.
pub const ALL_AAD_CONTEXTS: [&str; 1] = [AAD_CONTEXT_MASTER_KEY_WRAP];
