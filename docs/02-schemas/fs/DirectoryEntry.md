---
id: fs.DirectoryEntry
kind: schema
title: "DirectoryEntry"
section: "§3.13"
fbs_source: "schemas/fs/FileSystemEntry.fbs#DirectoryEntry"
status: draft
verified_by: []
---

# DirectoryEntry

Une entrée (fichier ou sous-répertoire) dans un
[`fs.DirectoryBlock`](DirectoryBlock.md). C'est la structure qui porte,
**en clair avant chiffrement**, tout ce qui constitue la navigation FS —
noms, tailles, chaînage.

## Champs

```
--8<-- "fs/DirectoryEntry.table.md"
```

## Points structurants

- `first_block_hash` pointe vers un [`fs.FileBlock`](FileBlock.md) ou un
  autre [`fs.DirectoryBlock`](DirectoryBlock.md) — c'est le `block_hash`
  d'un `BlockEntry` de type donnée (block_index 0..k-1, voir
  [`dispersal.BlockEntry`](../dispersal/BlockEntry.md)), **jamais** un
  `stripe_id`, qui ne sert qu'au regroupement erasure coding.
- `encryption_salt` (16 octets d'un CSPRNG, neuf à chaque création ou
  réémission, jamais réutilisé) + `key_version` + l'index du bloc dérivent
  [`crypto.k-block`](../../03-crypto/k-block.md) pour chaque bloc de cet
  élément. `key_version` est lisible **ici uniquement par le Connecteur** —
  voir [`crypto.master-key-chain`](../../03-crypto/master-key-chain.md#pourquoi-deux-emplacements)
  pour le pourquoi de ce doublon délibéré avec
  [`dispersal.BlockEntry`](../dispersal/BlockEntry.md).
- Contrairement au `DispersalManifest`, cette structure n'est **jamais**
  transmise ni indexée telle quelle sur le réseau — voir
  [`protocols.fs-structure`](../../04-protocols/fs-structure.md) pour la
  vue d'ensemble complète de l'encodage FS.

## Capacité

Mesure (Phase 1, `impl/protocol`, test `layout::directory_block_reference_capacity_is_measured`) :
avec un nom de 32 o, un type MIME de 24 o et sans métadonnée libre, **333
entrées** tiennent dans un `DirectoryBlock` (65 506 o de clair, `next_hash`
compris). La capacité réelle dépend des longueurs : le Connecteur mesure
chaque bloc avant émission et chaîne par `next_hash` au-delà.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
