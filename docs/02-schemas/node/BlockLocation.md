---
id: node.BlockLocation
kind: schema
title: "BlockLocation"
section: "§4.4 (ajout post-V2)"
fbs_source: "schemas/node/ContainerFile.fbs#BlockLocation"
status: draft
verified_by: []
---

# BlockLocation

!!! info "Ajout post-V2 — index local uniquement"
    Comme [`node.ContainerFile`](ContainerFile.md), absente de la
    spécification d'origine. Voir
    [`protocols.stockage-physique`](../../04-protocols/stockage-physique.md).

Localisation physique d'un bloc précis : quel conteneur, quel slot.

## Champs

```
--8<-- "node/BlockLocation.table.md"
```

## Ce n'est pas une table du NodeManifest

Contrairement à toutes les autres tables `.fbs` de ce projet,
`BlockLocation` **n'est jamais sérialisée** dans le fichier FlatBuffers
`NodeManifest` compacté (§3.5) ni publiée nulle part. Elle décrit
uniquement la **forme** d'un enregistrement individuel stocké dans le cache
SQLite/LMDB rapide du Nœud — une ligne par bloc, indexée par `block_hash`.

Deux raisons à cette séparation :

1. **Échelle** : un Nœud hébergeant 1 TiO par utilisateur peut approcher
   les 67 millions de blocs (voir
   [`protocols.index-adaptatif`](../../04-protocols/index-adaptatif.md)) —
   recompacter un fichier FlatBuffers unique à chaque écriture de bloc
   serait prohibitif, exactement le problème qui a motivé l'arbre d'index
   adaptatif côté `DispersalManifest`.
2. **Fréquence de mutation** : une entrée `BlockLocation` change à chaque
   écriture/suppression de bloc individuel — un ordre de grandeur plus
   fréquent que les mutations de [`node.ContainerFile`](ContainerFile.md)
   (qui ne change qu'à la création d'un nouveau conteneur ou à sa
   suppression complète).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
