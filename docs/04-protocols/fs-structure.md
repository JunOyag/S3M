---
id: protocols.fs-structure
kind: narrative
title: "Structure du Système de Fichiers"
section: "§3.13"
status: draft
verified_by: []
---

# Structure du Système de Fichiers (Encodage dans les Blocs de Données)

Contrairement au `DispersalManifest`, qui n'indexe que des blocs bruts à des
fins de redondance, la structure FS (noms, dossiers, tailles, contenu) est
encodée **directement dans le contenu en clair des blocs de données**
(indices 0 à k-1), invisible au Nœud comme aux partenaires puisque chiffrée
sous `K_block` avant tout envoi.

## Adressage

Le « hash du 1er bloc » référencé par une entrée FS correspond au
`block_hash` d'un [`dispersal.BlockEntry`](../02-schemas/dispersal/BlockEntry.md)
de type donnée — **pas** au `stripe_id`, qui ne sert qu'au regroupement pour
l'erasure coding.

## Bloc Répertoire

Le répertoire racine (pointé par `fs_root_hash`) est un
[`fs.DirectoryBlock`](../02-schemas/fs/DirectoryBlock.md) ; au-delà de sa
capacité, `next_hash` chaîne vers un bloc de continuation.

## Bloc Fichier

Un fichier est une chaîne de [`fs.FileBlock`](../02-schemas/fs/FileBlock.md).
Le dernier bloc, si incomplet, est complété par un padding à zéro ;
`size_bytes` fait foi pour distinguer contenu réel et padding.

## Immuabilité & modification {: #immuabilite }

Une chaîne de blocs, une fois écrite, n'est **pas** modifiée en place —
l'adressage par contenu rendrait toute édition en milieu de chaîne
invalidante en cascade jusqu'au premier bloc. Modifier un fichier signifie
le **réémettre intégralement** (nouvelle chaîne, nouveau
`first_block_hash`, mise à jour en cascade jusqu'à `fs_root_hash`,
copy-on-write comme pour l'arbre d'index — voir
[`protocols.dispersion-transactionnelle`](dispersion-transactionnelle.md)).
Les blocs de l'ancienne version deviennent orphelins et sont supprimés via
[`protocols.tombstones`](tombstones.md).

## Navigation

Lister un répertoire ou lire un fichier consiste à résoudre
`first_block_hash`/`next_hash` de proche en proche (chemin direct au Nœud
en fonctionnement normal, voir
[`protocols.acces-applicatif`](acces-applicatif.md)) plutôt qu'à interroger
l'arbre `IndexNode`, mécanisme purement interne au Nœud pour la redondance.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
