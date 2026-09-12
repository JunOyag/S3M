---
id: fs.Attributes
kind: schema
title: "Attributes"
section: "§3.13"
fbs_source: "schemas/fs/FileSystemEntry.fbs#Attributes"
status: draft
verified_by: []
---

# Attributes

Attributs POSIX-like d'une entrée FS.

## Champs

```
--8<-- "fs/Attributes.table.md"
```

`modified_at` est le champ arbitre de la résolution de conflit multi-appareils
« dernier écrit gagne » — voir
[`protocols.write-queue`](../../04-protocols/write-queue.md#resolution-de-conflit).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
