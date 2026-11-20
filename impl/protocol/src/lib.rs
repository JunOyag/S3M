//! p2p-storage-protocol — logique protocolaire commune au Nœud et au
//! Connecteur (spec V3, `impl/TECH_STACK.md`). Aucune I/O.
//!
//! - [`fb`] : types FlatBuffers générés par `flatc` depuis `schemas/**/*.fbs`
//!   (Phase 1). **Ne pas éditer** `src/generated/` : régénérer avec
//!   `bash impl/protocol/gen.sh`.
//! - [`dht`] : enveloppes DHT signées et règles de vérification
//!   (`network.dht-directory`, partie commune).
//! - [`layout`] : capacités de bloc mesurées sur les types générés.

#[allow(
    clippy::all,
    clippy::pedantic,
    dead_code,
    unused_imports,
    non_snake_case,
    non_camel_case_types,
    unsafe_op_in_unsafe_fn,
    mismatched_lifetime_syntaxes
)]
#[rustfmt::skip]
mod generated;

/// Espaces de noms FlatBuffers (`P2PStorage.Dispersal`, `.Emergency`,
/// `.FS`, `.Node`, `.Dht`).
pub use generated::p2_pstorage as fb;

pub mod dht;
pub mod dispersal;
pub mod exchange;
pub mod index;
pub mod layout;
pub mod local_api;
