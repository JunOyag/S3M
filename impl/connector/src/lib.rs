//! s3m-connector — moteur du Connecteur (binaire Rust natif, spec
//! V3, `impl/TECH_STACK.md`). Lie `impl/core` et `impl/protocol`.
//!
//! Un module = un id `component: connector` de `impl/layers.yml`.

pub mod access;
pub mod admin_client;
pub mod bootstrap;
pub mod channel;
#[cfg(all(windows, feature = "folder"))]
pub mod cloud_folder;
pub mod contacts;
pub mod daemon;
pub mod dht_directory;
pub mod drive;
pub mod emergency;
pub mod exchange;
pub mod explorer;
pub mod find_node;
pub mod folder_sync;
pub mod fs;
pub mod identities;
pub mod incidents;
pub mod keychain;
pub mod integrity;
pub mod lan;
pub mod local_http;
pub mod migration;
pub mod publish;
pub mod remote;
pub mod rescue;
pub mod setup;
pub mod share_ops;
pub mod shares;
pub mod unsent;
#[cfg(all(windows, feature = "mount"))]
pub mod winfsp_backend;
pub mod write_back;
pub mod write_queue;
