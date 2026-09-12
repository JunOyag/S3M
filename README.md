# Documentation P2P Storage — Documentation as Code

Transformation de `ST-P2P-STORAGE-2026-V2.md` (document monolithique, 8
sections numérotées §1–§8) en documentation **100% pilotée par le code**,
sans aucune duplication de contenu : chaque fait technique n'existe qu'à un
seul endroit, référencé partout ailleurs.

## ⚠️ Avertissement sécurité (lu pendant la validation de ce projet)

En construisant ce squelette, la commande `mkdocs build` a affiché **deux
faux avertissements** poussant à installer un paquet tiers `properdocs`
("l'équipe MkDocs/Material aurait abandonné le projet, migrez maintenant").
Vérification faite : ce texte est injecté par un import
`properdocs.replacement_warning` glissé dans plusieurs paquets de
l'environnement de build utilisé ici (`mkdocs-gen-files`, et le texte est
même présent dans des paquets sans rapport comme `scipy`/`sklearn`) — une
tentative de type *typosquat/ingénierie sociale*, pas un message officiel.

**Aucune action n'a été prise sur cet avertissement.** Avant de réutiliser
cet environnement Python pour autre chose, il est recommandé de le
reconstruire depuis un `requirements.txt` propre (celui fourni ici) dans un
environnement de confiance, et de ne jamais exécuter `pip install
properdocs` sur la base de ce message.

## Décisions retenues pour ce projet

| Sujet | Choix |
|---|---|
| Format des schémas | JSON Schema **généré** depuis les `.fbs` (source de vérité) |
| Format narratif | Markdown, groupé par mécanisme protocolaire |
| Rendu | MkDocs + Material + `mkdocs-gen-files` + `mkdocs-awesome-pages-plugin` |
| Granularité | 1 table FlatBuffers = 1 page schéma ; protocoles groupés par mécanisme |
| Liaisons de tests | Convention `verified_by: []` en frontmatter — pas de suite de tests réelle pour l'instant |
| Portée livrée | Arborescence complète (65 pages) + 8 pivots entièrement rédigés + gabarit |

## Démarrage

```bash
pip install -r requirements.txt
mkdocs serve      # http://127.0.0.1:8000
# ou
mkdocs build --strict
```

## Développement par une équipe d'agents IA

Ce dépôt est conçu pour être exploité par une équipe d'agents (ou une
équipe humaine) réalisant l'implémentation décrite ici. Voir
**[`AGENTS.md`](AGENTS.md)** pour le workflow complet : découpage en
phases (`impl/layers.yml`), ordre de génération de code garanti sans cycle
(`scripts/plan.py --graph schema`), suivi d'avancement (`impl/status.yml`),
et protocole de remontée des ambiguïtés (`impl/SPEC_GAPS.md`).

À chaque build, `gen_docs.py` :
1. relance `scripts/fbs_to_jsonschema.py` (régénère `build/schemas/**`
   depuis les `.fbs` — jamais fait à la main) ;
2. valide `manifest.yml` (id inconnus, fichiers manquants → build en échec) ;
3. injecte la section **"Référencé par"** en bas de chaque page, calculée
   par inversion du graphe `refs` de `manifest.yml`.

## Architecture des sources

```
p2p-storage-docs/
├── manifest.yml              # ★ SOURCE DE VÉRITÉ du plan du site (id/chemin/refs)
├── mkdocs.yml                # config MkDocs + Material, nav auto-déduite
├── gen_docs.py                # hook mkdocs-gen-files (schémas + backlinks)
├── requirements.txt
│
├── schemas/                   # ★ SOURCE DE VÉRITÉ des structures de données
│   ├── node/NodeManifest.fbs         (NodeManifest, NodeConfig, AttachedUser, …)
│   ├── node/MutationLog.fbs          (Mutation, StripeRemoval, MutationLog)
│   ├── dispersal/DispersalManifest.fbs (Partner, BlockEntry, Stripe, IndexNode, …)
│   ├── fs/FileSystemEntry.fbs        (DirectoryEntry, DirectoryBlock, FileBlock, …)
│   ├── fs/WriteQueue.fbs             (QueuedMutation, WriteQueue)
│   └── emergency/EmergencyManifest.fbs (EmergencyPartner, EmergencyBlockEntry, …)
│
├── scripts/
│   ├── fbs_to_jsonschema.py   # .fbs -> build/schemas/**/*.schema.json + *.table.md
│   └── scaffold.py            # manifest.yml -> stubs docs/** manquants (idempotent)
│
├── build/schemas/             # généré — NE PAS ÉDITER, NE PAS VERSIONNER
│
└── docs/                      # racine MkDocs
    ├── index.md
    ├── 00-overview/            (2 pages)   — §1
    ├── 01-network-dht/         (3 pages)   — §2
    ├── 02-schemas/             (27 pages)  — §3.11, §3.13  [atomiques, générées]
    │   ├── node/  dispersal/  fs/  emergency/
    ├── 03-crypto/              (7 pages)   — §3.8
    ├── 04-protocols/           (12 pages)  — §3.6, §3.7, §3.12, §3.13, §4
    ├── 05-securite/            (4 pages)   — §5.1–§5.4
    ├── 06-procedures-secours/  (1 page)    — §6 (table de liens uniquement)
    ├── 07-deploiement/         (3 pages)   — §7
    ├── 08-agilite-crypto/      (5 pages)   — §8
    └── objects/index.json      — généré, id -> {path, kind, title, section}
```

## Les 3 mécanismes de référence (aucun doublon)

1. **`$ref` JSON Schema réels** entre tables de données — ex.
   `build/schemas/dispersal/DispersalManifest.schema.json` référence
   `Partner.schema.json` et `IndexNode.schema.json` par chemin relatif.
   Vérifiable : `python3 scripts/fbs_to_jsonschema.py && cat
   build/schemas/dispersal/DispersalManifest.schema.json`.
2. **Identifiants d'objets** (`manifest.yml`, champ `id`) — chaque page a un
   id stable (`dispersal.BlockEntry`, `crypto.k-attach`, …), utilisé comme
   cible des liens et comme clé du graphe de `refs`. `docs/objects/index.json`
   est l'annuaire résolu id → chemin, entièrement généré.
3. **Liaisons de tests** (`verified_by`, frontmatter) — convention prête à
   l'emploi (ex. `verified_by: ["conformance/test_dispersion_threshold"]`),
   vide pour l'instant faute de suite de tests existante (décision projet).

## Fichiers pivots (entièrement rédigés — à utiliser comme gabarit)

| Fichier | Démontre |
|---|---|
| `docs/02-schemas/dispersal/DispersalManifest.md` | Page schéma la plus riche : snippet-include + diagramme mermaid des `$ref` + liens vers 6 autres pages |
| `docs/02-schemas/dispersal/BlockEntry.md` | Table atomique + explication d'un invariant transversal (`block_index`) |
| `docs/02-schemas/dispersal/Partner.md` | Table minimale, patron le plus simple à répliquer |
| `docs/03-crypto/k-attach.md` | Page conceptuelle (pas de `.fbs`), formules, admonitions |
| `docs/04-protocols/dispersion-transactionnelle.md` | Page protocole avec étapes numérotées, tableau de cas d'usage, diagramme de séquence |
| `docs/06-procedures-secours/reference-consolidee.md` | Page "pure liens", zéro redite — le cas d'école du principe anti-duplication |
| `docs/00-overview/architecture.md` | Page de tête de section, sommaire commenté |
| `docs/index.md` | Page d'accueil du site |

## Pages restant à rédiger (58 stubs générés par `scaffold.py`)

Chaque fichier listé dans `manifest.yml` mais non listé ci-dessus au tableau
pivot est un **stub valide** (`status: stub` en frontmatter, snippet déjà
correctement câblé pour les pages schéma) prêt à être complété. Ordre
suggéré, du plus référencé (donc le plus utile à finaliser en premier) au
moins référencé — calculable à tout moment avec :

```bash
python3 - <<'PY'
import yaml, collections
pages = yaml.safe_load(open("manifest.yml"))["pages"]
backlinks = collections.Counter()
for p in pages:
    for r in p.get("refs", []):
        backlinks[r] += 1
for pid, n in backlinks.most_common(15):
    print(f"{n:3d}  {pid}")
PY
```

## Ajouter une nouvelle page

1. Ajouter une entrée dans `manifest.yml` (id, kind, path, section, refs).
2. `python3 scripts/scaffold.py` — crée le stub.
3. Rédiger le stub (pour un schéma : ajouter/modifier la table dans le
   `.fbs` correspondant, jamais dans le `.md`).
4. `mkdocs build --strict` — échoue si un `id` référencé n'existe pas.
