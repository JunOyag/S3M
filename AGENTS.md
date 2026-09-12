# AGENTS.md — Développement par une équipe d'agents IA

Ce dépôt est une **spécification pilotée par le code**, pas encore une
implémentation. Ce document explique comment une équipe d'agents (un
orchestrateur + des agents de travail, humains ou IA) peut s'en servir pour
construire le système décrit — sans se marcher dessus, sans diverger de la
spec, et avec une traçabilité doc ↔ tests ↔ code.

## 0. Ce qui existe déjà, ce qu'il faut décider

**Existe déjà** : le protocole est entièrement spécifié (`docs/`), les
structures de données sont formalisées (`schemas/**/*.fbs`), le plan de
dépendances est outillé (`scripts/plan.py`, `impl/layers.yml`), **et la
stack technique est tranchée** (`impl/TECH_STACK.md`) :

| Composant | Langage | Répertoire |
|---|---|---|
| Noyau partagé (crypto, Reed-Solomon, VDF) | Rust → natif + WASM | `impl/core` |
| Nœud (démon hébergeur) | Rust, lie `impl/core` natif | `impl/node` |
| Connecteur (client) | TypeScript / Bun, importe `impl/core` en WASM | `impl/connector` |

Voir `impl/TECH_STACK.md` pour la justification complète (pourquoi Rust,
pourquoi un noyau partagé plutôt que deux implémentations crypto, pourquoi
lier `chiavdf` plutôt que réimplémenter le VDF, bibliothèques précises par
composant). `impl/layers.yml` porte désormais un champ `component` par id,
directement exploitable pour assigner une tâche au bon sous-répertoire.

**Décisions encore ouvertes**, plus mineures :

- Bibliothèque WebDAV précise côté Connecteur (`impl/TECH_STACK.md` propose
  deux options, à trancher à l'usage).
- Suite de tests : `verified_by: []` (frontmatter de chaque page) est une
  convention prête à l'emploi, encore vide — c'est cette équipe qui va la
  peupler (voir §3).

## 1. Trois graphes, trois usages — ne pas les confondre

C'est le piège le plus probable si une équipe se lance sans lire cette
section :

| Graphe | Source | Nature | Usage |
|---|---|---|---|
| Renvois documentaires | `manifest.yml` (`refs`) | **Cyclique** — deux concepts peuvent se référencer mutuellement (ex. `crypto.k-block` ↔ `fs.DirectoryEntry`) | Navigation et contexte (quelles pages lire avant de coder telle mécanique) — **pas un ordre d'implémentation** |
| Dépendances de schéma | `build/schemas/**/*.schema.json` (`$ref`) | **DAG garanti acyclique** (une table ne peut pas s'auto-contenir) | Ordre de génération de code (structs/types) — mécaniquement fiable |
| Phasage architectural | `impl/layers.yml` | Jugement humain, non dérivé d'un graphe | Ordre d'implémentation de la *logique* protocolaire (ce qu'aucun algorithme ne peut décider à la place d'un architecte) |

```bash
# Ordre de génération de code (DAG réel, sûr) :
python3 scripts/plan.py --graph schema --json impl/schema-order.json

# Clusters de concepts mutuellement couplés en doc (informatif, PAS un ordre de build) :
python3 scripts/plan.py --graph manifest
```

`scripts/plan.py --graph manifest` affiche un avertissement explicite
lorsqu'il détecte des cycles, précisément pour éviter qu'un agent ne le
prenne à tort pour un ordre de build.

## 2. Workflow proposé

```
┌─ Orchestrateur ──────────────────────────────────────────────┐
│ 1. Tranche les décisions ouvertes (§0)                        │
│ 2. python3 scripts/plan.py --graph schema  → ordre de codegen │
│ 3. Lit impl/layers.yml phase par phase                        │
│ 4. Pour la phase courante, assigne 1 agent (ou paire) par id   │
│    ou cluster d'id à impl/layers.yml                          │
│ 5. Attend que impl/status.yml passe "done" pour toute la phase│
│    avant d'ouvrir la phase suivante                            │
└────────────────────────────────────────────────────────────────┘
```

### Contexte à fournir à un agent de travail pour une tâche donnée

Pour l'id `X` qui lui est assigné :

1. `docs/<chemin de X selon manifest.yml>` — la page elle-même.
2. Les pages des `refs` déclarés pour `X` dans `manifest.yml` (contexte,
   pas nécessairement du code déjà écrit — voir avertissement §1).
3. Si `X` est une table de schéma : la table `.fbs` source
   (`fbs_source` en frontmatter) et son `.schema.json` généré.
4. `impl/layers.yml` pour situer `X` dans le phasage global.
5. Rien d'autre — ne pas donner accès à l'intégralité du dépôt de code en
   cours de construction par les autres agents, pour éviter les
   dépendances implicites non documentées.

## 3. Définition du "terminé" pour une tâche

Une tâche sur l'id `X` est terminée quand, **et seulement quand** :

- [ ] Le code implémente exactement le comportement décrit dans la page
      `X` — toute divergence constatée avec la spec est signalée dans
      `impl/SPEC_GAPS.md` (voir §5), **jamais** résolue par une
      improvisation silencieuse.
- [ ] Des tests couvrent les invariants explicitement énoncés dans la page
      (ex. "seuil k+2 avant dispersion du parent" pour
      `protocols.dispersion-transactionnelle`).
- [ ] `impl/status.yml` : l'entrée `X` passe à `status: done`, `owner`
      renseigné, `tests` listés.
- [ ] `manifest.yml` : le champ `verified_by` de la page `X` est mis à jour
      avec les mêmes identifiants de test (c'est le seul champ de
      `manifest.yml` qu'un agent de code doit toucher — tout le reste du
      plan documentaire reste stable).
- [ ] `mkdocs build --strict` passe toujours (une page éditée ne doit
      jamais casser un lien ou une ancre).
- [ ] Aucun fichier hors du périmètre assigné n'a été modifié (voir §4).

## 4. Éviter que les agents se marchent dessus

Disposition de code (voir `impl/TECH_STACK.md` pour la justification des
trois composants) :

```
impl/
├── layers.yml              # phasage, avec `component` par id
├── status.yml                # suivi d'implémentation
├── TECH_STACK.md               # décision de stack + bibliothèques retenues
├── SPEC_GAPS.md                  # remontées d'ambiguïté (voir §5)
├── core/                           # Rust, natif + WASM — phases 0, 3 (partie erasure-coding), 6 (partie sérialisation), 7
│   ├── src/
│   └── Cargo.toml
├── node/                            # Rust natif, lie impl/core — phases 2-6, ids `component: node`
│   ├── src/
│   └── Cargo.toml
└── connector/                        # TypeScript/Bun, importe impl/core en WASM — ids `component: connector`
    ├── src/
    └── package.json
```

Pour un id marqué `component: node+connector` dans `impl/layers.yml`
(protocole à deux acteurs, ex. `protocols.migration-noeud`), **deux tâches
distinctes** sont créées — une par composant, assignées à deux agents
différents si besoin, chacun ne touchant que son propre répertoire.

**Règle stricte** : un agent ne modifie que le sous-répertoire
correspondant à son id/cluster assigné, plus son entrée dans
`impl/status.yml` et le champ `verified_by` de sa page dans `manifest.yml`.
Toute modification d'un `.fbs` ou de `impl/core` (contrats partagés entre
composants) doit être signalée à l'orchestrateur avant d'être faite — un
changement de schéma ou de primitive partagée peut invalider le travail
d'un autre agent en cours sur un composant qui en dépend (voir le DAG de
schéma, §1).

## 5. Quand la spec est ambiguë ou semble fausse

Un agent qui, en implémentant, découvre un cas non couvert ou une
incohérence : **ne pas improviser silencieusement**. Ajouter une entrée à
`impl/SPEC_GAPS.md` :

```markdown
## <id concerné> — <titre court>
**Constat** : <ce qui manque ou semble incohérent>
**Question** : <ce qu'il faut trancher>
**Impact si non résolu** : <bloquant / contournable temporairement comment>
```

L'orchestrateur (ou un humain) tranche, met à jour la page `docs/`
concernée en conséquence (c'est elle qui reste la source de vérité), *puis*
l'implémentation reprend — jamais l'inverse.

## 6. Rappel — hygiène du dépôt documentaire

Ce dépôt reste vivant pendant le chantier de code : toute clarification de
spec découverte en implémentant (§5) doit être répercutée dans `docs/`, pas
seulement dans le code. Avant de considérer une phase terminée :

```bash
python3 scripts/status.py          # 100% des pages toujours en status draft/final ?
mkdocs build --strict               # 0 lien/ancre cassé ?
```

Voir `README.md` pour les conventions complètes du projet documentaire
(format `$ref`, granularité, etc.) — ce fichier ne les répète pas.
