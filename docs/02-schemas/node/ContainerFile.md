---
id: node.ContainerFile
kind: schema
title: "ContainerFile"
section: "§4.4 (ajout post-V2)"
fbs_source: "schemas/node/ContainerFile.fbs#ContainerFile"
status: draft
verified_by: []
---

# ContainerFile

!!! info "Ajout post-V2"
    Absent de la spécification d'origine (`VolumeConfig`, §3.11, ne
    définissait qu'un point de montage, jamais la disposition physique des
    blocs dessus). Voir
    [`protocols.stockage-physique`](../../04-protocols/stockage-physique.md)
    pour la justification complète et les algorithmes.

Un fichier de conteneur de **4 GiO** (65536 slots de 64 KiO chacun),
appartenant à un **seul** propriétaire logique — jamais mélangé entre
propriétaires.

## Champs

```
--8<-- "node/ContainerFile.table.md"
```

## Pourquoi 4 GiO exactement

`4 GiO / 64 KiO = 65536` — un nombre de slots exact, sans reste. Le bitmap
d'occupation qui en découle (1 bit/slot) pèse exactement `65536 / 8 = 8192`
octets (8 KiO), négligeable au regard des 4 GiO utiles.

## Sur quel volume ? {: #sur-quel-volume }

`volume_id` référence [`node.VolumeConfig`](VolumeConfig.md) — indispensable
dès qu'un Nœud déclare plus d'un volume
([`node.NodeConfig`](NodeConfig.md), `volumes: [VolumeConfig]`) : sans ce
champ, `file_path` (relatif à un `mount_path`) serait ambigu, puisque rien
d'autre dans `ContainerFile` ne permet de savoir de quel volume ce
`mount_path` doit être pris. Voir
[`protocols.stockage-physique`](../../04-protocols/stockage-physique.md#selection-du-volume-a-la-creation-dun-conteneur)
pour la politique de sélection du volume à la création d'un conteneur.

## Un propriétaire, jamais deux

C'est la propriété la plus importante de ce schéma : un `ContainerFile` ne
contient **jamais** de blocs appartenant à deux propriétaires différents
(`owner_type` + `owner_id`). Le coût est un peu d'espace potentiellement
sous-utilisé pour un propriétaire léger ; le bénéfice est une **suppression
en masse en O(nombre de conteneurs)** plutôt qu'en O(nombre de blocs) —
déterminant pour la rupture immédiate d'un partenaire fraudeur
([`securite.blacklist-fraude`](../../05-securite/blacklist-fraude.md#rupture-bilaterale-immediate))
ou le départ d'un utilisateur.

## Localisation fine des blocs : `BlockLocation`

Ce schéma ne dit **pas** quel bloc précis se trouve dans quel slot — ce
serait bien trop volumineux pour être recompacté à chaque mutation
(potentiellement des millions d'entrées, même problème d'échelle qu'un
[`dispersal.IndexNode`](../dispersal/IndexNode.md) plat). Cette
localisation fine vit dans
[`node.BlockLocation`](BlockLocation.md), un enregistrement individuel du
cache SQLite/LMDB local (§3.5) — jamais dans `NodeManifest` lui-même.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
