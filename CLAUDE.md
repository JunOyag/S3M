# CLAUDE.md — Instructions pour Claude Code sur ce dépôt

Ce dépôt combine deux sous-projets qui doivent être fusionnés côte à côte :
- `p2p-storage-docs/` (spec pilotée par le code : `docs/`, `schemas/`, `manifest.yml`,
  `impl/layers.yml`, `impl/status.yml`, `impl/TECH_STACK.md`, `AGENTS.md`) — déjà fourni.
- `impl/core/`, `impl/node/`, `impl/connector/` (ce scaffold) — squelette de code à faire
  croître phase par phase.

**Avant toute action, lis `AGENTS.md` en entier.** Ce fichier CLAUDE.md ne le duplique pas
(principe du projet : aucun fait à deux endroits) — il ne fait que rappeler les points sur
lesquels une session Claude Code se trompe le plus souvent.

## Règles non négociables (résumé — la source de vérité reste `AGENTS.md`)

1. **Périmètre** : une session ne touche que le sous-répertoire correspondant au
   `component` de l'id assigné (`core` / `node` / `connector`), plus sa propre entrée dans
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

## État actuel

- Phase en cours : **Phase 0 — Fondations cryptographiques** (`impl/layers.yml`), tout en
  `component: core`. Voir `impl/status.yml` pour la liste exacte des ids et leur statut
  (`not_started` pour tous au démarrage de ce scaffold).
- `impl/core` contient des stubs annotés (`todo!()`) — un id de la Phase 0 = une fonction à
  compléter, jamais une réécriture du fichier entier.
- `impl/node` et `impl/connector` sont des placeholders vides (Phase 2+) — ne pas y toucher
  avant que la Phase 0 soit `done` pour tous ses ids.

## Commandes utiles

```bash
cd impl/core && cargo test              # tests Phase 0
cd impl/core && cargo clippy -- -D warnings
python3 scripts/plan.py --graph schema --json impl/schema-order.json
python3 scripts/status.py               # cohérence docs/ vs impl/status.yml
mkdocs build --strict                   # ne doit jamais casser après un commit de code
```
