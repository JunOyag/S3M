---
id: network.RescueGrant
kind: schema
title: "RescueGrant"
section: "protocols.echange-blocs"
fbs_source: "schemas/network/BlockExchange.fbs#RescueGrant"
status: draft
verified_by: []
---

# RescueGrant

Table source : `schemas/network/BlockExchange.fbs#RescueGrant`.

## Champs

```
--8<-- "network/RescueGrant.table.md"
```

Autorisation de lecture de secours délivrée par un Nœud à la clé anonyme d'un appareil (`grant_pub`), valable au plus 15 552 000 s. `covered_node_ids` liste les anciens `node_id` couverts, effectifs seulement si la DHT porte un [`network.SignedMigrationPointer`](SignedMigrationPointer.md) valide vers l'émetteur. Règles : [`protocols.echange-blocs`](../../04-protocols/echange-blocs.md#autorisation-de-secours).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
