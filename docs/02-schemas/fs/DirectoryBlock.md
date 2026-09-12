---
id: fs.DirectoryBlock
kind: schema
title: "DirectoryBlock"
section: "§3.13"
fbs_source: "schemas/fs/FileSystemEntry.fbs#DirectoryBlock"
status: draft
verified_by: []
---

# DirectoryBlock

Bloc de répertoire — liste de [`fs.DirectoryEntry`](DirectoryEntry.md),
chaîné par `next_hash` au-delà de la capacité d'un bloc.

## Champs

```
--8<-- "fs/DirectoryBlock.table.md"
```

Le répertoire racine (pointé par `fs_root_hash`, voir
[`network.dht-directory`](../../01-network-dht/dht-directory.md)) est un
`DirectoryBlock` sans `DirectoryEntry` parent — c'est pourquoi son
`encryption_salt`/`key_version` sont portés directement par l'entrée DHT
User plutôt que par une entrée de répertoire.

Navigation détaillée (résolution `first_block_hash`/`next_hash` de proche en
proche) dans
[`protocols.fs-structure`](../../04-protocols/fs-structure.md).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
