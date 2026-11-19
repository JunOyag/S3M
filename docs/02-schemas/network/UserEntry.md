---
id: network.UserEntry
kind: schema
title: "UserEntry"
section: "§3.9, §3.11"
fbs_source: "schemas/network/UserEntry.fbs#UserEntry"
status: draft
verified_by: []
---

# UserEntry

Table source : `schemas/network/UserEntry.fbs#UserEntry` (V3).

## Champs

```
--8<-- "network/UserEntry.table.md"
```

Entrée DHT d'un User, indexée par `user_dht_key` et signée par
`sig_priv_user` — `pub_user` n'est jamais publiée. La preuve VDF porte sur
`0x00 ‖ sig_pub_user`. Durée de vie 315 360 000 s, republication réactive à
chaque écriture confirmée qui change `fs_root_hash`, ou de secours après
31 536 000 s. **Ni IP ni port** : le Connecteur n'accepte aucune connexion
entrante. `file_identifier` : `"USER"`. Voir [`network.dht-directory`](../../01-network-dht/dht-directory.md).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
