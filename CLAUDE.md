# CLAUDE.md — Instructions pour Claude Code sur ce dépôt

Ce dépôt combine deux sous-projets qui doivent être fusionnés côte à côte :
- `p2p-storage-docs/` (spec pilotée par le code : `docs/`, `schemas/`, `manifest.yml`,
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

## État actuel (2026-11-19)

- **Orchestration** : Claude Code est la seule IA du projet, orchestrateur compris. Les
  consignes de `.github/agents/` et `.clinerules/` (Copilot, Cline) ne font plus foi.
- **Spec V3 intégrée** (branche `docs/spec-v3`, entrée « Spec V3 » de `impl/SPEC_GAPS.md`) :
  Connecteur en Rust natif, plus de WASM, convention KDF unique, `K_block` par position,
  identité VDF marquée, enveloppe DHT signée.
- **Phase 0 terminée** (11 ids `done`, spec V3) et **Phase 1 terminée** : 41 types
  FlatBuffers générés dans `impl/protocol` (`bash impl/protocol/gen.sh`, flatc 23.5.26
  sous Docker). **Phase 2 terminée** (dht-directory, bootstrap, stockage-physique).
  Prochaine phase : Phase 3 (`impl/layers.yml`).
- `protocols.stockage-physique` (node) était `done` avant la Phase 0 : écart d'ordre hérité,
  accepté tel quel.
- L'essai V1 de `network.dht-directory` reste archivé sur la branche locale
  `archive/dht-directory-v1` (référence uniquement, jamais fusionnée).
- Builds : `cargo test` en local (Windows) ; tests `--features vdf` et clippy associé via
  `bash impl/docker-test.sh` (Docker).

## Commandes utiles

```bash
cd impl/core && cargo test              # tests Phase 0
cd impl/core && cargo clippy -- -D warnings
python3 scripts/plan.py --graph schema --json impl/schema-order.json
python3 scripts/status.py               # cohérence docs/ vs impl/status.yml
mkdocs build --strict                   # ne doit jamais casser après un commit de code
```
