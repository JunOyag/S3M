# impl/connector — placeholder

Ne pas implémenter avant Phase 0 (core) ET Phase 1 (node, protocole réseau
minimal) terminées — le Connecteur dépend du Nœud pour toute écriture
confirmée (§3.12).

Quand la phase démarre : `bun init`, consommer `impl/core` compilé en WASM
(`wasm-pack build --features wasm --target bundler`), libp2p-js pour la
couche réseau si nécessaire côté Connecteur (§7.3 — exécutable Bun portable).
