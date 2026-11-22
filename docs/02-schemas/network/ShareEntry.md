---
id: network.ShareEntry
kind: schema
title: "ShareEntry"
section: "§3.12.6"
fbs_source: "schemas/network/ShareEntry.fbs#ShareEntry"
status: draft
verified_by: []
---

# ShareEntry

Table source : `schemas/network/ShareEntry.fbs#ShareEntry` (ajout du 2026-11-22).

## Champs

```
--8<-- "network/ShareEntry.table.md"
```

Pointeur vivant d'un partage, indexé par `SHA-256(sig_pub_share ‖ "share")`
et signé par `sig_priv_share`, clé du seul propriétaire : un destinataire
peut le lire, pas le réécrire. `file_identifier` : `"SHAR"`. Le champ
`pointer` chiffre un `SharePointer` sous `K_share_content` (AAD
`"dht-share-pointer"`). Règles :
[`protocols.partage`](../../04-protocols/partage.md#pointeur).

## SharePointer

```
--8<-- "network/SharePointer.table.md"
```

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
