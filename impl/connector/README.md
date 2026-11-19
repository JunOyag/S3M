# impl/connector — Connecteur (Rust natif)

Binaire client de l'Utilisateur : moteur DHT, système de fichiers, lecteur monté
(WinFsp puis FUSE), écriture différée, API locale et dashboard statique
(TypeScript, interface uniquement). Lie `impl/core` et `impl/protocol`.

Décision de stack : `impl/TECH_STACK.md` (spec V3, 2026-11-19). Le prototype
TypeScript/Bun d'octobre 2026 est archivé sur la branche locale
`archive/dht-directory-v1`.

Ne pas implémenter avant que les ids `component: connector` de la phase en cours
soient ouverts dans `impl/layers.yml`.
