---
id: network.SignedRescueGrant
kind: schema
title: "SignedRescueGrant"
section: "protocols.echange-blocs"
fbs_source: "schemas/network/BlockExchange.fbs#SignedRescueGrant"
status: draft
verified_by: []
---

# SignedRescueGrant

Table source : `schemas/network/BlockExchange.fbs#SignedRescueGrant`.

## Champs

```
--8<-- "network/SignedRescueGrant.table.md"
```

[`network.RescueGrant`](RescueGrant.md) sérialisée, signée en Ed25519 par `priv_node` de l'émetteur sur `L("s3m/sig/rescue-grant/v1") ‖ grant` — même séparation de contexte que les signatures DHT.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
