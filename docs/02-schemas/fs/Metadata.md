---
id: fs.Metadata
kind: schema
title: "Metadata"
section: "§3.13"
fbs_source: "schemas/fs/FileSystemEntry.fbs#Metadata"
status: draft
verified_by: []
---

# Metadata

Métadonnée libre clé/valeur portée par une [`fs.DirectoryEntry`](DirectoryEntry.md).

## Champs

```
--8<-- "fs/Metadata.table.md"
```

Liste extensible, sans schéma imposé sur le contenu — permet d'ajouter des
attributs applicatifs (tags, provenance, etc.) sans modification de schéma.
Comme tout le contenu FS, encodée en clair **avant** chiffrement
[`crypto.k-block`](../../03-crypto/k-block.md), donc invisible au Nœud.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
