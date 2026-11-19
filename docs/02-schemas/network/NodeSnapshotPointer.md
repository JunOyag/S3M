---
id: network.NodeSnapshotPointer
kind: schema
title: "NodeSnapshotPointer"
section: "§3.9, §3.11"
fbs_source: "schemas/network/NodeEntry.fbs#NodeSnapshotPointer"
status: draft
verified_by: []
---

# NodeSnapshotPointer

Table source : `schemas/network/NodeEntry.fbs#NodeSnapshotPointer` (V3).

## Champs

```
--8<-- "network/NodeSnapshotPointer.table.md"
```

Clair chiffré sous [`crypto.k-node-self`](../../03-crypto/k-node-self.md)
dans le champ `snapshot_ciphertext` de
[`network.NodeEntry`](NodeEntry.md) : point d'entrée de la cartographie de
dispersion du Nœud. Chiffré pour qu'aucun observateur ne puisse
reconstruire le graphe des relations de dispersion à partir des
partenaires ; seul le Nœud (via sa seed) le déchiffre, y compris après une
restauration complète.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
