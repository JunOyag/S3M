# impl/connector — Connecteur (Rust natif)

Moteur client de l'Utilisateur (spec V3, `impl/TECH_STACK.md`). Lie
`impl/core` et `impl/protocol`. Un module = un id `component: connector` de
`impl/layers.yml`.

| Module | Id |
|---|---|
| `dht_directory` | `network.dht-directory` (client Kademlia, identité éphémère) |

Tests : `cargo test` (démarre des Nœuds réels de `impl/node` sur 127.0.0.1).
