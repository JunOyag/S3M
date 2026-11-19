//! p2p-storage-connector — moteur du Connecteur (binaire Rust natif, spec
//! V3, `impl/TECH_STACK.md`). Lie `impl/core` et `impl/protocol`.
//!
//! Un module = un id `component: connector` de `impl/layers.yml`.

pub mod bootstrap;
pub mod dht_directory;
pub mod emergency;
pub mod fs;
pub mod integrity;
pub mod migration;
pub mod write_back;
pub mod write_queue;
