---
id: node.UserQuota
kind: schema
title: "UserQuota"
section: "§3.11"
fbs_source: "schemas/node/NodeManifest.fbs#UserQuota"
status: draft
verified_by: []
---

# UserQuota

Quota alloué à un utilisateur rattaché, exprimé en octets.

## Champs

```
--8<-- "node/UserQuota.table.md"
```

Consultée lors de la synchronisation multi-Connecteurs
([`protocols.quota-sync`](../../04-protocols/quota-sync.md)) et de
l'intégration de l'espace de secours
([`protocols.espace-secours`](../../04-protocols/espace-secours.md)) : dans
les deux cas, les mutations excédant ce quota sont rejetées par timestamp
croissant, jamais interprétées par contenu (le Nœud ne voit que des blocs
opaques, voir [`crypto.k-block`](../../03-crypto/k-block.md)).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
