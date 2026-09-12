---
id: home
kind: narrative
title: "Documentation P2P Storage — Accueil"
section: "—"
status: draft
---

# Spécification Technique — Protocole P2P de Stockage Distribué

Cette documentation remplace le document monolithique `ST-P2P-STORAGE-2026-V2.md`
par un ensemble de fichiers **interconnectés par référence** plutôt que par
copier-coller : chaque fait technique n'existe qu'à **un seul endroit**, et
toute autre page qui en a besoin y renvoie.

## Comment c'est organisé

| Dossier | Contenu | Qui l'édite |
|---|---|---|
| `schemas/**/*.fbs` | Schémas FlatBuffers — **source de vérité** des structures de données | À la main, rarement |
| `docs/02-schemas/**` | 1 page par table (`NodeManifest`, `DispersalManifest`, …), champs **inclus automatiquement** depuis le `.fbs` | Génère le squelette (`scaffold.py`) + prose métier à la main |
| `docs/03-crypto/`, `docs/04-protocols/`, `docs/05-securite/`, … | Pages narratives regroupées **par mécanisme**, qui `$ref`-érencent les schémas plutôt que de les redécrire | À la main |
| `docs/06-procedures-secours/reference-consolidee.md` | Table de synthèse — **uniquement des liens**, aucune redite | À la main (liens) |
| `docs/objects/index.json` | Index `id → page` et graphe de liens retour | **100% généré**, ne pas éditer |
| `manifest.yml` | Plan du site — id, chemin, section d'origine, références sortantes | **Source de vérité unique** du plan |

## Principe anti-duplication

1. Un champ de structure de données n'est tapé **qu'une fois** : dans le `.fbs`.
   `scripts/fbs_to_jsonschema.py` en dérive le JSON Schema (`$ref` réels) et un
   tableau Markdown, inclus par les pages `docs/02-schemas/**` via
   `pymdownx.snippets` (`--8<--`).
2. Un lien entre deux pages n'est déclaré **qu'une fois**, dans `manifest.yml`
   (champ `refs`, sur la page source). La section *"Référencé par"* en bas de
   chaque page est calculée par **inversion** de ce graphe (`gen_docs.py`) —
   jamais tenue à jour à la main des deux côtés.
3. Le plan de navigation n'est pas dupliqué dans `mkdocs.yml` : il est déduit
   de l'arborescence `docs/` par `mkdocs-awesome-pages-plugin`.

## Démarrer

```bash
pip install -r requirements.txt
mkdocs serve
```

Voir [`README.md`](https://example.invalid/README.md) à la racine du dépôt
pour le détail des conventions et la liste des pages restant à rédiger.

## Table des matières

- [Vue d'ensemble & Architecture](00-overview/architecture.md) — `overview.architecture`
- [Réseau & DHT](01-network-dht/vdf-identity.md) — `network.*`
- [Schémas de données](02-schemas/dispersal/DispersalManifest.md) — `node.*`, `dispersal.*`, `fs.*`, `emergency.*`
- [Chiffrement & Clés](03-crypto/k-attach.md) — `crypto.*`
- [Protocoles](04-protocols/dispersion-transactionnelle.md) — `protocols.*`
- [Sécurité & PoS](05-securite/pos-challenges.md) — `securite.*`
- [Procédures de secours (référence consolidée)](06-procedures-secours/reference-consolidee.md) — `secours.*`
- [Déploiement](07-deploiement/disaster-recovery.md) — `deploiement.*`
- [Agilité cryptographique / post-quantique](08-agilite-crypto/kem-vs-nike.md) — `agilite.*`
