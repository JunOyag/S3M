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

Le `block_hash` est le hash SHA-256 du bloc chiffré complet de 65 536
octets. Le « hash du 1er bloc » référencé par une entrée FS correspond au
`block_hash` d'un [`dispersal.BlockEntry`](../02-schemas/dispersal/BlockEntry.md)
de type donnée — **pas** au `stripe_id`, qui ne sert qu'au regroupement pour
l'erasure coding.

## Bloc Répertoire

Le répertoire racine (pointé par `fs_root_hash`) est un
[`fs.DirectoryBlock`](../02-schemas/fs/DirectoryBlock.md) ; au-delà de sa
capacité, `next_hash` chaîne vers un bloc de continuation.

## Bloc Fichier

Un fichier est une chaîne de [`fs.FileBlock`](../02-schemas/fs/FileBlock.md).
Un `FileBlock` contient au plus `FILE_BLOCK_DATA_BYTES` octets de `data`
(capacité mesurée par un test, voir le format de bloc de
[`crypto.k-block`](../03-crypto/k-block.md#format-dun-bloc-chiffre)) ; le
dernier bloc est complété par un padding à zéro ; `size_bytes` fait foi
pour distinguer contenu réel et padding.

La capacité d'un `DirectoryBlock` est réduite d'un peu plus de 30 octets
par l'en-tête, le nonce et le tag du format de bloc : la valeur « ≤ 300
entrées » est à re-mesurer par un test.

## Immuabilité & modification {: #immuabilite }

Une chaîne de blocs, une fois écrite, n'est **pas** modifiée en place —
l'adressage par contenu rendrait toute édition en milieu de chaîne
invalidante en cascade jusqu'au premier bloc. Modifier un fichier signifie
le **réémettre intégralement** : nouvel `encryption_salt`, nouvelle chaîne
de blocs (chiffrée du dernier bloc vers le premier,
[`crypto.k-block`](../03-crypto/k-block.md)), nouveau `first_block_hash`,
mise à jour de l'entrée de répertoire parente et donc de tous les blocs de
répertoire jusqu'à `fs_root_hash`, en cascade et copy-on-write comme pour
l'arbre d'index (voir
[`protocols.dispersion-transactionnelle`](dispersion-transactionnelle.md)).
Chaque répertoire réémis reçoit lui aussi un `encryption_salt` neuf ; celui
du répertoire racine est porté par le
[`network.UserEntryPlaintext`](../02-schemas/network/UserEntryPlaintext.md)
et mis à jour avec `fs_root_hash`. Les blocs de l'ancienne version
deviennent orphelins et sont supprimés via
[`protocols.tombstones`](tombstones.md) une fois la nouvelle version
entièrement confirmée.

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
