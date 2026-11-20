---
id: network.DispersalRootPointer
kind: schema
title: "DispersalRootPointer"
section: "§3.9, §3.11"
fbs_source: "schemas/network/DispersalEntry.fbs#DispersalRootPointer"
status: draft
verified_by: []
---

# DispersalRootPointer

Table source : `schemas/network/DispersalEntry.fbs#DispersalRootPointer` (V3).

## Champs

```
--8<-- "network/DispersalRootPointer.table.md"
```

Clair chiffré sous [`crypto.k-attach`](../../03-crypto/k-attach.md) :
amorçage de la lecture de l'arbre d'index. `dispersal_root_partners`
publie les partenaires du stripe racine (sans eux, le premier bloc serait
introuvable) ; `dispersal_root_salt` est le sel du nœud racine, qui dérive
sa clé `K_dispersal_block`
([`crypto.k-dispersal`](../../03-crypto/k-dispersal.md)).

`dispersal_root_stripe` (ajout du 2026-11-20, additif) décrit le stripe
racine : `BlockEntry` de chaque fragment (hash, indice, partenaire référencé
dans `dispersal_root_partners`). Les fragments étant demandés par hash
([`protocols.echange-blocs`](../../04-protocols/echange-blocs.md)), connaître
les partenaires ne suffit pas sans leurs hashes. `dispersal_root_hash` est
le hash du bloc 0 de ce stripe (le nœud racine chiffré).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
