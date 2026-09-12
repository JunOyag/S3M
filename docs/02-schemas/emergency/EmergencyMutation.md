---
id: emergency.EmergencyMutation
kind: schema
title: "EmergencyMutation"
section: "§3.12.4"
fbs_source: "schemas/emergency/EmergencyManifest.fbs#EmergencyMutation"
status: draft
verified_by: []
---

# EmergencyMutation

Mutation FS en attente de réconciliation — même forme que
[`fs.QueuedMutation`](../fs/QueuedMutation.md), pour permettre au Connecteur
réconciliateur de reconstruire les
[`fs.DirectoryEntry`](../fs/DirectoryEntry.md) sans consulter le
`DispersalManifest`.

## Champs

```
--8<-- "emergency/EmergencyMutation.table.md"
```

Réconciliée par **n'importe quel Connecteur du même `user_id`**, pas
forcément l'émetteur — voir
[`protocols.espace-secours`](../../04-protocols/espace-secours.md#decouverte-et-reconciliation)
pour le protocole complet, y compris la vérification de présence des blocs
avant envoi des mutations FS (pour éliminer tout risque de pointeur
orphelin, voir [`protocols.write-queue`](../../04-protocols/write-queue.md)).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
