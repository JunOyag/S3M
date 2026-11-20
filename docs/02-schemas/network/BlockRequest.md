---
id: network.BlockRequest
kind: schema
title: "BlockRequest"
section: "protocols.echange-blocs"
fbs_source: "schemas/network/BlockExchange.fbs#BlockRequest"
status: draft
verified_by: []
---

# BlockRequest

Table source : `schemas/network/BlockExchange.fbs#BlockRequest`.

## Champs

```
--8<-- "network/BlockRequest.table.md"
```

Requête du protocole [`protocols.echange-blocs`](../../04-protocols/echange-blocs.md) : un `credential` optionnel (union `UserCredential` / `RescueCredential` / `DelegatedCredential`) et un `body` (union des dix requêtes). `file_identifier` `BREQ`, une requête par flux, taille ≤ 1 048 576 o.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
