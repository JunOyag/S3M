---
id: network.SignedMigrationPointer
kind: schema
title: "SignedMigrationPointer"
section: "§5.2, §3.11"
fbs_source: "schemas/network/DhtEnvelope.fbs#SignedMigrationPointer"
status: draft
verified_by: []
---

# SignedMigrationPointer

Table source : `schemas/network/DhtEnvelope.fbs#SignedMigrationPointer` (V3).

## Champs

```
--8<-- "network/SignedMigrationPointer.table.md"
```

Pointeur de migration signé par `priv_node_recovery`, publié dans le champ
`migration_pointer` de l'entrée Node **de l'ancien** `node_id`. La
signature Ed25519 porte sur
`L("s3m/sig/migration-pointer/v1") ‖ payload` et se vérifie avec le
`pub_node_recovery` déjà publié dans l'entrée, sans dépendre de la clé
compromise. Voir
[`securite.incidents-compromissions`](../../05-securite/incidents-compromissions.md).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
