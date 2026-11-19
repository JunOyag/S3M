---
id: network.VdfProof
kind: schema
title: "VdfProof"
section: "§2.1, §3.11"
fbs_source: "schemas/network/DhtEnvelope.fbs#VdfProof"
status: draft
verified_by: []
---

# VdfProof

Table source : `schemas/network/DhtEnvelope.fbs#VdfProof` (V3).

## Champs

```
--8<-- "network/VdfProof.table.md"
```

Preuve VDF d'identité jointe aux entrées Node et User. `identity` est
l'identité **marquée** (`key_algorithm ‖ clé publique brute`) ; `y` et `pi`
font 100 octets chacun. Le discriminant `Δ` n'est **pas** transmis : le
vérificateur le recalcule depuis `identity`. Règles et paramètres :
[`network.vdf-identity`](../../01-network-dht/vdf-identity.md).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
