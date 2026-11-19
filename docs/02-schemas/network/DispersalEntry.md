---
id: network.DispersalEntry
kind: schema
title: "DispersalEntry"
section: "§3.9, §3.11"
fbs_source: "schemas/network/DispersalEntry.fbs#DispersalEntry"
status: draft
verified_by: []
---

# DispersalEntry

Table source : `schemas/network/DispersalEntry.fbs#DispersalEntry` (V3).

## Champs

```
--8<-- "network/DispersalEntry.table.md"
```

Entrée DHT du DispersalManifest d'un couple (User, Node), indexée par
`SHA-256(K_attach)` et signée par `sig_priv_dispersal`, dont la clé
publique est en clair dans l'entrée. Durée de vie 15 552 000 s, republiée
toutes les 2 592 000 s. `file_identifier` : `"DISP"`. Voir [`network.dht-directory`](../../01-network-dht/dht-directory.md).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
