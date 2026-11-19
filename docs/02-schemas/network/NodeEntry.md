---
id: network.NodeEntry
kind: schema
title: "NodeEntry"
section: "§3.9, §3.11"
fbs_source: "schemas/network/NodeEntry.fbs#NodeEntry"
status: draft
verified_by: []
---

# NodeEntry

Table source : `schemas/network/NodeEntry.fbs#NodeEntry` (V3).

## Champs

```
--8<-- "network/NodeEntry.table.md"
```

Entrée DHT d'un Nœud, indexée par `pub_node`, transportée dans une
[`network.DhtEnvelope`](DhtEnvelope.md) signée par `priv_node`. Durée de
vie 15 552 000 s, republiée toutes les 2 592 000 s avec un `timestamp` à
jour. `file_identifier` : `"NODE"`.

`pub_node_recovery` est immuable ; `migration_pointer` est optionnel.
Régimes d'expiration et lissage : [`network.dht-directory`](../../01-network-dht/dht-directory.md).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
