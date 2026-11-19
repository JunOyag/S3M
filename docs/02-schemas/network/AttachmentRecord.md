---
id: network.AttachmentRecord
kind: schema
title: "AttachmentRecord"
section: "§3.8, §3.11"
fbs_source: "schemas/network/UserEntry.fbs#AttachmentRecord"
status: draft
verified_by: []
---

# AttachmentRecord

Table source : `schemas/network/UserEntry.fbs#AttachmentRecord` (V3).

## Champs

```
--8<-- "network/AttachmentRecord.table.md"
```

Un attachement, courant ou passé, du User à un Nœud : de quoi re-dériver
[`crypto.k-attach`](../../03-crypto/k-attach.md) depuis la seed seule
(`node_id`, `salt`). Les champs `kem_ciphertext` et
`wrapped_shared_secret` sont vides pour `key_algorithm = 0` et servent au
mode KEM ([`agilite.k-attach-kem`](../../08-agilite-crypto/k-attach-kem.md)).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
