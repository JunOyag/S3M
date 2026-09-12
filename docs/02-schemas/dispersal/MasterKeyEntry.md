---
id: dispersal.MasterKeyEntry
kind: schema
title: "MasterKeyEntry"
section: "§3.8, §3.11"
fbs_source: "schemas/dispersal/DispersalManifest.fbs#MasterKeyEntry"
status: draft
verified_by: []
---

# MasterKeyEntry

Un maillon de la chaîne de clés maîtresses.

## Champs

```
--8<-- "dispersal/MasterKeyEntry.table.md"
```

!!! note "Ne fait pas partie du DispersalManifest lui-même"
    Bien que déclarée dans le même fichier `.fbs` par cohérence de schéma,
    cette table est en réalité publiée dans l'entrée DHT **User** (chiffrée
    sous `K_self`), pas dans le `DispersalManifest` — voir
    [`network.dht-directory`](../../01-network-dht/dht-directory.md).

`wrapped_key` contient `master_key[version]` chiffrée sous la
`master_key` courante — mécanisme de re-wrap plat complet décrit dans
[`crypto.master-key-chain`](../../03-crypto/master-key-chain.md), qui reste
la page de référence pour comprendre *pourquoi* cette structure existe.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
