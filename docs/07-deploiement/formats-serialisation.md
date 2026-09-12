---
id: deploiement.formats-serialisation
kind: narrative
title: "Formats de Sérialisation et Performance"
section: "§7.2"
status: draft
verified_by: []
---

# Formats de Sérialisation et Performance

- **Format réseau P2P** : en-têtes et protocoles gérés via FlatBuffers (ou
  Cap'n Proto) pour une sérialisation/désérialisation à coût zéro
  (zero-copy) et un très faible usage CPU/RAM. Voir les schémas sources
  sous `schemas/**/*.fbs`, dont dérivent toutes les pages
  [`02-schemas`](../02-schemas/dispersal/DispersalManifest.md).
- **Stockage local** : base SQLite en mode WAL ou LMDB pour les accès
  clé-valeur instantanés — voir
  [`node.MutationLog`](../02-schemas/node/MutationLog.md) pour le détail du
  cycle append-only → compaction.
- **Payload** : octets bruts chiffrés avec en-tête fixe de 2 octets pour la
  version.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
