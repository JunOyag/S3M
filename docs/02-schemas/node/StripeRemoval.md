---
id: node.StripeRemoval
kind: schema
title: "StripeRemoval"
section: "§3.11"
fbs_source: "schemas/node/MutationLog.fbs#StripeRemoval"
status: draft
verified_by: []
---

# StripeRemoval

Payload de journal représentant la suppression d'une
[`dispersal.Stripe`](../dispersal/Stripe.md) complète.

## Champs

```
--8<-- "node/StripeRemoval.table.md"
```

Utilisé notamment lors de la purge différée qui suit une dispersion
(copy-on-write, voir
[`protocols.dispersion-transactionnelle`](../../04-protocols/dispersion-transactionnelle.md))
et lors du remplacement a posteriori d'un stripe partiel avec padding (voir
[`protocols.erasure-coding`](../../04-protocols/erasure-coding.md)).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
