---
id: node.VolumeConfig
kind: schema
title: "VolumeConfig"
section: "§3.11"
fbs_source: "schemas/node/NodeManifest.fbs#VolumeConfig"
status: draft
verified_by: []
---

# VolumeConfig

Un volume physique monté par le Nœud, déclaré dans
[`node.NodeConfig`](NodeConfig.md).

## Champs

```
--8<-- "node/VolumeConfig.table.md"
```

`volume_id` est l'identifiant stable référencé par
[`node.ContainerFile`](ContainerFile.md#sur-quel-volume) pour savoir sur
quel volume physique un conteneur de blocs a été placé — indispensable dès
qu'un Nœud déclare plusieurs volumes. Voir
[`protocols.stockage-physique`](../../04-protocols/stockage-physique.md)
pour le mécanisme complet de stockage physique des blocs (ajout post-V2).

`mount_path`, combiné à `volume_id`, **est** utilisé par le protocole pour
localiser physiquement les fichiers de conteneur sur disque
(`<mount_path>/blocks/...`) — contrairement à l'adressage logique des blocs
eux-mêmes (par `block_hash`, voir
[`protocols.dispersion-transactionnelle`](../../04-protocols/dispersion-transactionnelle.md)),
qui reste indépendant de tout chemin physique. `mount_path` sert aussi de
simple référence pour l'administrateur en cas de réinstallation.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
