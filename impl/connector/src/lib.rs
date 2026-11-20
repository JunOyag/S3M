//! p2p-storage-connector — moteur du Connecteur (binaire Rust natif, spec
//! V3, `impl/TECH_STACK.md`). Lie `impl/core` et `impl/protocol`.
//!
//! Un module = un id `component: connector` de `impl/layers.yml`.

pub mod access;
pub mod bootstrap;
pub mod daemon;
pub mod dht_directory;
pub mod drive;
pub mod emergency;
pub mod exchange;
pub mod fs;
pub mod incidents;
pub mod integrity;
pub mod local_http;
pub mod migration;
pub mod publish;
#[cfg(all(windows, feature = "mount"))]
pub mod winfsp_backend;
pub mod write_back;
pub mod write_queue;
