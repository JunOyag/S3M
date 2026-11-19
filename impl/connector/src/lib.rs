//! p2p-storage-connector — moteur du Connecteur (binaire Rust natif, spec
//! V3, `impl/TECH_STACK.md`). Lie `impl/core` et `impl/protocol`.
//!
//! Un module = un id `component: connector` de `impl/layers.yml`.

pub mod bootstrap;
pub mod dht_directory;
pub mod fs;
