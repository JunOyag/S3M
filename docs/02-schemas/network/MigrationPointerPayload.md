---
id: network.MigrationPointerPayload
kind: schema
title: "MigrationPointerPayload"
section: "§5.2, §3.11"
fbs_source: "schemas/network/DhtEnvelope.fbs#MigrationPointerPayload"
status: draft
verified_by: []
---

# MigrationPointerPayload

Table source : `schemas/network/DhtEnvelope.fbs#MigrationPointerPayload` (V3).

## Champs

```
--8<-- "network/MigrationPointerPayload.table.md"
```

Contenu signé d'un pointeur de migration d'identité du Nœud, sérialisé
puis porté par [`network.SignedMigrationPointer`](SignedMigrationPointer.md).
`old_node_id` doit être celui de l'entrée Node qui porte le pointeur ;
`seq` est monotone (premier pointeur : 1), ce qui empêche le rejeu d'un
ancien pointeur et départage deux pointeurs concurrents. Règles de suivi :
[`securite.incidents-compromissions`](../../05-securite/incidents-compromissions.md).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
