# Contenu de ce scaffold

Généré à fusionner tel quel à la racine du dépôt `p2p-storage-docs`
(celui contenant déjà README.md, AGENTS.md, docs/, schemas/, impl/*.yml).

- `CLAUDE.md`                    — instructions de session pour Claude Code
- `impl/core/Cargo.toml`         — crate Rust, Phase 0
- `impl/core/src/lib.rs`         — point d'entrée, un module par id crypto
- `impl/core/src/error.rs`       — type d'erreur unique du crate
- `impl/core/src/keys.rs`        — conversion Ed25519<->X25519, sig_priv_user
- `impl/core/src/k_attach.rs`    — K_attach + sig_priv_dispersal
- `impl/core/src/k_dispersal.rs` — K_dispersal_content / K_dispersal_block
- `impl/core/src/k_block.rs`     — K_block (contenu réel des blocs)
- `impl/core/src/k_self.rs`      — K_self
- `impl/core/src/k_node_self.rs` — K_node_self
- `impl/core/src/master_key_chain.rs` — rotation de clé, re-wrap plat
- `impl/core/src/vdf.rs`         — binding FFI chiavdf (stub)
- `impl/core/tests/rfc_vectors.rs` — tests requis avant tout `status: done`
- `impl/node/README.md`, `impl/connector/README.md` — placeholders Phase 2+

Toutes les fonctions sont `todo!()` intentionnellement — c'est la matière de
la Phase 0. Chaque fichier porte en commentaire la référence exacte à la
section du protocole (ST-P2P-STORAGE-2026-V2.md) et/ou à la page docs/
correspondante.

Premier pas concret recommandé : ouvrir Claude Code sur ce dépôt fusionné,
lui donner uniquement `docs/03-crypto/keys.md` (ou la page équivalente) +
`impl/core/src/keys.rs`, et lui demander d'implémenter
`ed25519_priv_to_x25519` / `ed25519_pub_to_x25519` avec les vecteurs RFC 7748.
C'est le plus petit id de la Phase 0, sans dépendance sur les autres modules.
