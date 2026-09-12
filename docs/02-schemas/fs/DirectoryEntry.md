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
- `encryption_salt` + `key_version` dérivent
  [`crypto.k-block`](../../03-crypto/k-block.md) pour tous les blocs de cet
  élément. `key_version` est lisible **ici uniquement par le Connecteur** —
  voir [`crypto.master-key-chain`](../../03-crypto/master-key-chain.md#pourquoi-deux-emplacements)
  pour le pourquoi de ce doublon délibéré avec
  [`dispersal.BlockEntry`](../dispersal/BlockEntry.md).
- Contrairement au `DispersalManifest`, cette structure n'est **jamais**
  transmise ni indexée telle quelle sur le réseau — voir
  [`protocols.fs-structure`](../../04-protocols/fs-structure.md) pour la
  vue d'ensemble complète de l'encodage FS.

## Capacité

Pour un nom et un type MIME de longueur usuelle, une entrée pèse environ 175
octets — soit **≤ 300 entrées par `DirectoryBlock`** (64 KiO), au-delà
duquel `next_hash` chaîne vers un bloc de continuation.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
