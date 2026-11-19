---
id: network.EmergencyEntry
kind: schema
title: "EmergencyEntry"
section: "§3.12.4, §3.11"
fbs_source: "schemas/network/EmergencyEntry.fbs#EmergencyEntry"
status: draft
verified_by: []
---

# EmergencyEntry

Table source : `schemas/network/EmergencyEntry.fbs#EmergencyEntry` (V3).

## Champs

```
--8<-- "network/EmergencyEntry.table.md"
```

Entrée DHT de l'[`emergency.EmergencyManifest`](../emergency/EmergencyManifest.md)
d'un `user_id`, signée par `sig_priv_emergency`. `seq` est en clair pour
que les pairs rejettent sans déchiffrer toute entrée dont `seq` n'est pas
strictement supérieur au leur. Durée de vie 15 552 000 s, **ni
republication ni suppression**. `file_identifier` : `"EMRG"`. Règle
d'écriture (lecture, fusion, `seq + 1`) :
[`protocols.espace-secours`](../../04-protocols/espace-secours.md).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
