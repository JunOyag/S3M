---
id: network.DeviceRecord
kind: schema
title: "DeviceRecord"
section: "§3.11"
fbs_source: "schemas/network/UserEntry.fbs#DeviceRecord"
status: draft
verified_by: [rotation::devices_are_named_merged_and_shown_in_node_messages]
---

# DeviceRecord

Table source : `schemas/network/UserEntry.fbs#DeviceRecord` (ajout du 2026-11-26).

## Champs

```
--8<-- "network/DeviceRecord.table.md"
```

Un appareil de l'Utilisateur, porté par le champ `devices` de
[`network.UserEntryPlaintext`](UserEntryPlaintext.md) : il n'existe que
chiffré sous `K_self`, lisible par l'Utilisateur sur ses seuls appareils.
`device_id` est stable par appareil ; `peer_id` est son identité réseau
auprès du Nœud courant, dont l'empreinte figure dans les messages « nouvel
appareil » ; `name` suit les règles de
[`deploiement.pseudos`](../../07-deploiement/pseudos.md#regles). `updated_at`
et `deleted` servent à la fusion entre appareils
([`securite.incidents-compromissions#nouvel-appareil`](../../05-securite/incidents-compromissions.md#nouvel-appareil)).
