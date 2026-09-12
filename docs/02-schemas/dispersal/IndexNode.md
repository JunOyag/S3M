---
id: dispersal.IndexNode
kind: schema
title: "IndexNode"
section: "§3.6, §3.11"
fbs_source: "schemas/dispersal/DispersalManifest.fbs#IndexNode"
status: draft
verified_by: []
---

# IndexNode

Nœud de l'arbre d'index adaptatif : feuille de
[`dispersal.Stripe`](Stripe.md) ou niveau d'indirection.

## Champs

```
--8<-- "dispersal/IndexNode.table.md"
```

- `is_leaf = true` → `stripes` rempli (contenu utilisateur).
- `is_leaf = false` → `children` rempli ; chaque `Stripe` de `children`
  encode, avec redondance, un `IndexNode` enfant.

Le mécanisme de croissance adaptative (facteur de branchement, profondeur
selon le volume) est détaillé dans
[`protocols.index-adaptatif`](../../04-protocols/index-adaptatif.md) —
cette page ne décrit que la structure, pas la logique de scaling.

Chaque `IndexNode` enfant est chiffré par bloc via
[`crypto.k-dispersal`](../../03-crypto/k-dispersal.md)
(`K_dispersal_block`) avant découpage en fragments — jamais en clair sur le
réseau, y compris pour ces niveaux internes.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
