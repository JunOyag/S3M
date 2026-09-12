---
id: fs.FileBlock
kind: schema
title: "FileBlock"
section: "§3.13"
fbs_source: "schemas/fs/FileSystemEntry.fbs#FileBlock"
status: draft
verified_by: []
---

# FileBlock

Bloc de contenu de fichier — fragment brut, chaîné par `next_hash`.

## Champs

```
--8<-- "fs/FileBlock.table.md"
```

Le dernier bloc de la chaîne, si son contenu utile ne remplit pas les
64 KiO, est complété par un **padding à zéro** jusqu'à la taille fixe du
bloc ; `size_bytes` (porté par la
[`fs.DirectoryEntry`](DirectoryEntry.md) parente) fait foi pour distinguer
le contenu réel du padding à la lecture.

**Immuabilité** : une chaîne de `FileBlock`, une fois écrite, n'est pas
modifiée en place (l'adressage par contenu rendrait toute édition en milieu
de chaîne invalidante en cascade). Modifier un fichier signifie le
**réémettre intégralement** — voir
[`protocols.fs-structure`](../../04-protocols/fs-structure.md#immuabilite).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
