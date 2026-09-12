---
id: fs.WriteQueue
kind: schema
title: "WriteQueue"
section: "§3.12.2"
fbs_source: "schemas/fs/WriteQueue.fbs#WriteQueue"
status: draft
verified_by: []
---

# WriteQueue

File d'attente locale complète du Connecteur — **jamais publiée sur la
DHT**, sur le même principe que [`node.MutationLog`](../node/MutationLog.md)
mais côté Connecteur.

## Champs

```
--8<-- "fs/WriteQueue.table.md"
```

`base_fs_root_hash` capture le `fs_root_hash` connu au moment de la mise en
file : comparé au `fs_root_hash` réel du Nœud à la resynchronisation, il
permet de détecter qu'un autre appareil a écrit entre-temps — voir
[`protocols.write-queue`](../../04-protocols/write-queue.md) pour le
protocole complet (mise en file, lecture pendant la panne, résolution de
conflit, plafond `Q_max`).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
