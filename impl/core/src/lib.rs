//! s3m-core — Phase 0 (impl/layers.yml)
//!
//! Ce crate ne fait AUCUNE I/O (réseau, disque, DHT). Il expose uniquement les
//! primitives cryptographiques et de sérialisation utilisées par `impl/node`
//! et `impl/connector` (Rust natif tous deux, spec V3).
//!
//! Un module = un id de `docs/03-crypto/*.md`. Ne pas ajouter de fonction qui
//! ne correspond à aucun id documenté — voir CLAUDE.md règle 4 (SPEC_GAPS.md)
//! si un besoin de code n'a pas de contrepartie dans la spec.

pub mod erasure;
pub mod error;
pub mod identity_derivation;
pub mod k_attach;
pub mod k_block;
pub mod k_dispersal;
pub mod k_node_self;
pub mod k_self;
pub mod keys;
pub mod labels;
pub mod master_key_chain;
pub mod symmetric_suite;
pub mod vdf;
pub mod version;

pub use error::CoreError;
