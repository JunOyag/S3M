---
id: fs.QueuedMutation
kind: schema
title: "QueuedMutation"
section: "§3.12.2"
fbs_source: "schemas/fs/WriteQueue.fbs#QueuedMutation"
status: draft
verified_by: []
---

# QueuedMutation

Une mutation FS en attente de synchronisation avec le Nœud, journalisée
côté Connecteur pendant une indisponibilité totale du réseau.

## Champs

```
--8<-- "fs/QueuedMutation.table.md"
```

- `block_hash` (pour `write_block`) : bloc déjà chiffré
  ([`crypto.k-block`](../../03-crypto/k-block.md)) en attente d'envoi.
- `entry` (pour `update_entry`) : nouvelle
  [`fs.DirectoryEntry`](DirectoryEntry.md).
- `blocks_to_delete` (pour `delete_entry`) : liste complète de la chaîne à
  tombstoner (voir [`protocols.tombstones`](../../04-protocols/tombstones.md))
  — **seul le Connecteur**, qui a déchiffré la chaîne, peut l'établir.

Voir [`protocols.write-queue`](../../04-protocols/write-queue.md) pour le
protocole complet de mise en file, de lecture pendant la panne et de
synchronisation au retour du Nœud.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
