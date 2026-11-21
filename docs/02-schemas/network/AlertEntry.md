---
id: network.AlertEntry
kind: schema
title: "AlertEntry"
section: "§3.11, §5.2"
fbs_source: "schemas/network/AlertEntry.fbs#AlertEntry"
status: draft
verified_by: []
---

# AlertEntry

Table source : `schemas/network/AlertEntry.fbs#AlertEntry` (ajout du 2026-11-21).

## Champs

```
--8<-- "network/AlertEntry.table.md"
```

Copie dans l'annuaire de la dernière alerte d'un Nœud, indexée par
`SHA-256(pub_node_announce ‖ "alert")` et signée par `priv_node_announce`.
Elle atteint les Utilisateurs même quand le Nœud est éteint ou aux mains
d'un attaquant. `file_identifier` : `"ALRT"`. Règles :
[`protocols.canal-noeud`](../../04-protocols/canal-noeud.md#annuaire).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
