---
id: network.DhtEnvelope
kind: schema
title: "DhtEnvelope"
section: "§3.9"
fbs_source: "schemas/network/DhtEnvelope.fbs#DhtEnvelope"
status: draft
verified_by: []
---

# DhtEnvelope

Table source : `schemas/network/DhtEnvelope.fbs#DhtEnvelope` (V3).

## Champs

```
--8<-- "network/DhtEnvelope.table.md"
```

Enveloppe de transport de **toute** entrée DHT. Le `payload` est la
sérialisation FlatBuffers de l'entrée, signée **telle que transmise** : le
vérificateur contrôle les octets reçus et ne réserialise jamais. La
signature couvre `L(libellé du type) ‖ payload` (séparation de contexte) et
n'est donc pas dans le buffer signé.

La clé de vérification dépend du type d'entrée, et `key_algorithm` doit
être cohérent avec le tag de l'identité prouvée par la VDF : voir
[`network.dht-directory`](../../01-network-dht/dht-directory.md) (§ Enveloppe signée) et
[`agilite.tag-hybride`](../../08-agilite-crypto/tag-hybride.md).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
