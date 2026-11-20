# CLAUDE.md — Instructions pour Claude Code sur ce dépôt

Ce dépôt combine deux sous-projets qui doivent être fusionnés côte à côte :
- `s3m-docs/` (spec pilotée par le code : `docs/`, `schemas/`, `manifest.yml`,
  `impl/layers.yml`, `impl/status.yml`, `impl/TECH_STACK.md`, `AGENTS.md`) — déjà fourni.
- `impl/core/`, `impl/protocol/`, `impl/node/`, `impl/connector/` — code Rust à faire
  croître phase par phase (voir `impl/TECH_STACK.md`).

**Avant toute action, lis `AGENTS.md` en entier.** Ce fichier CLAUDE.md ne le duplique pas
(principe du projet : aucun fait à deux endroits) — il ne fait que rappeler les points sur
lesquels une session Claude Code se trompe le plus souvent.

## Règles non négociables (résumé — la source de vérité reste `AGENTS.md`)

1. **Périmètre** : une session ne touche que le sous-répertoire correspondant au
   `component` de l'id assigné (`core` / `protocol` / `node` / `connector`), plus sa propre entrée dans
   `impl/status.yml` et le champ `verified_by` de sa page dans `manifest.yml`. Jamais autre
   chose. Un id `node+connector` = deux tâches séparées, pas une session qui touche les deux
   répertoires.
2. **Contexte minimal** : pour un id `X`, lire uniquement `docs/<chemin de X>.md`, ses `refs`
   déclarées dans `manifest.yml`, le `.fbs` source si `X` est un schéma, et la section de
   `impl/layers.yml` où `X` apparaît. Ne pas parcourir tout `impl/` en cours de construction
   par d'autres sessions.
3. **Ordre d'implémentation** : `impl/layers.yml`, phase par phase — jamais l'ordre des
   `refs` de `manifest.yml` (cyclique, informatif seulement). Vérifier
   `python3 scripts/plan.py --graph schema` pour l'ordre de codegen FlatBuffers.
4. **Ambiguïté ou incohérence de spec** : ne jamais improviser. Ajouter une entrée dans
   `impl/SPEC_GAPS.md` (format imposé dans ce fichier) et attendre arbitrage — voir
   `AGENTS.md` §5.
5. **Ne pas réimplémenter depuis zéro** : le VDF de Wesolowski (lier `chiavdf` via FFI) et
   Reed-Solomon (`reed-solomon-erasure`) sont des bibliothèques auditées à *lier*, jamais du
   code maison — voir `impl/TECH_STACK.md`, section "Bibliothèques à ne PAS réimplémenter".
6. **Définition de "terminé"** pour un id : voir `AGENTS.md` §3 (code conforme à la page +
   tests des invariants explicites + `impl/status.yml` à `done` + `verified_by` renseigné +
   `mkdocs build --strict` toujours vert). Ne jamais marquer `done` sans ces 5 conditions.

## État actuel (2026-11-20)

- **Orchestration** : Claude Code est la seule IA du projet, orchestrateur compris.
- **Spec V3 intégrée** (entrée « Spec V3 » de `impl/SPEC_GAPS.md`).
- **Phases 0 à 6 implémentées** (logique testée) ; voir `impl/status.yml` pour le détail.
  Reste `in_progress` : `deploiement.packaging` (exécutables, dashboards et image Docker
  livrés, dispersion, contrôles, publication DHT Node/User et snapshot du Nœud
  (restauration depuis la seed), partenariats et rattachements automatiques, carte du
  réseau, traversée de NAT et application de barre des tâches S3m.exe livrés ; dashboards incomplets —
  `impl/SPEC_GAPS.md`). Lecteur Windows (WinFsp) livré ; FUSE viendra ensuite.
- **Échange de blocs** : spécifié et livré (`protocols.echange-blocs`, 2026-11-20) —
  libp2p requête/réponse `/s3m/blocks/1`, à côté de la DHT (Kademlia). Reste à
  l'assembler dans les binaires (`deploiement.packaging`).
- **Phase 7 (post-quantique) reportée** : optionnelle pour un MVP et contraire à la V3
  (seul le tag 0 est accepté).
- L'essai V1 de `network.dht-directory` reste archivé sur `archive/dht-directory-v1`.
- Builds : `cargo test` en local (Windows) ; lecteur : `--features mount` (WinFsp + LLVM) ;
  VDF natif Windows : `--features vdf` (MSVC + CMake + LLVM, DLL MPIR dans le PATH) ;
  exécutables : `bash impl/package-windows.sh` ; tests `--features vdf` via
  `bash impl/docker-test.sh` ; types FlatBuffers via `bash impl/protocol/gen.sh`.

## Commandes utiles

```bash
cd impl/core && cargo test              # tests Phase 0
cd impl/core && cargo clippy -- -D warnings
python3 scripts/plan.py --graph schema --json impl/schema-order.json
python3 scripts/status.py               # cohérence docs/ vs impl/status.yml
mkdocs build --strict                   # ne doit jamais casser après un commit de code
```
