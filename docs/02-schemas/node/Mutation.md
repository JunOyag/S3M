---
id: node.Mutation
kind: schema
title: "Mutation"
section: "§3.11"
fbs_source: "schemas/node/MutationLog.fbs#Mutation"
status: draft
verified_by: []
---

# Mutation

Une entrée individuelle du journal append-only du Nœud, avant compaction en
FlatBuffers complet.

## Champs

```
--8<-- "node/Mutation.table.md"
```

`payload` est une union portant, selon `op`, un
[`dispersal.BlockEntry`](../dispersal/BlockEntry.md), un
[`node.StripeRemoval`](StripeRemoval.md), un
[`node.BlacklistedPartner`](BlacklistedPartner.md) ou un
[`node.PartnerAccount`](PartnerAccount.md). Rejouée au démarrage avant
chargement du dernier snapshot compacté — voir
[`node.MutationLog`](MutationLog.md) pour le conteneur complet.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
