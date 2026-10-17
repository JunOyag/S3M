---
id: protocols.stockage-physique
kind: narrative
title: "Stockage Physique des Blocs sur Volume"
section: "§4.4 (ajout post-V2)"
status: draft
verified_by: []
---

# Stockage Physique des Blocs sur Volume

!!! info "Ajout post-V2"
    Ce mécanisme est absent de `ST-P2P-STORAGE-2026-V2.md`.
    [`node.VolumeConfig`](../02-schemas/node/VolumeConfig.md) (§3.11) ne
    définissait qu'un point de montage — jamais la façon dont les blocs de
    64 KiO sont réellement disposés dessus. Sans ce mécanisme, un Nœud
    hébergeant des dizaines de millions de blocs
    ([`protocols.index-adaptatif`](index-adaptatif.md)) créerait un fichier
    par bloc : désastre en inodes et en fragmentation pour la plupart des
    systèmes de fichiers.

## Principe : conteneurs de 4 GiO segmentés par propriétaire

Chaque volume ([`node.VolumeConfig`](../02-schemas/node/VolumeConfig.md))
héberge un ensemble de **fichiers de conteneur**
([`node.ContainerFile`](../02-schemas/node/ContainerFile.md)), taille fixe
**4 GiO**, contenant chacun **65536 slots** de 64 KiO — une correspondance
exacte (`4 GiO / 64 KiO = 65536`, aucun reste).

Un ou plusieurs conteneurs sont alloués **par propriétaire logique**
(`owner_type` + `owner_id`) :

| `owner_type` | Propriétaire | Nature des blocs |
|---|---|---|
| `AttachedUser` | Un utilisateur rattaché | Les k blocs de données locaux, jamais dispersés (§1, [`overview.architecture`](../00-overview/architecture.md)) |
| `Partner` | Un partenaire de troc | Parité hébergée en réciprocité (troc entrant, [`node.PartnerAccount`](../02-schemas/node/PartnerAccount.md)) |
| `EmergencyDepositor` | Un utilisateur en détresse (secours) | Dépôts temporaires reçus via [`protocols.espace-secours`](espace-secours.md), bornés par `emergency_reserved_bytes` |

**Un conteneur n'héberge jamais deux propriétaires.** C'est le choix
structurant de ce design — voir plus bas pourquoi.

## Disposition binaire d'un conteneur

```
Octet 0                 8192              8192 + 65536×65536 (= 8192 + 4 GiO)
│                        │                                                  │
├── occupied_bitmap ─────┤├──────────────── 65536 slots de 64 KiO ─────────┤
│   (8192 o, 1 bit/slot) ││ slot 0 │ slot 1 │ slot 2 │ ... │ slot 65535    │
```

- **En-tête** : les 8192 premiers octets portent `occupied_bitmap` — 1 bit
  par slot, `0` = libre/trou, `1` = occupé.
- **Sérialisation du bitmap** : pour le slot d’index `i`, le bit `i % 8` de
  l’octet `i / 8` (division entière, indices à partir de zéro) indique son
  occupation. Le slot `0` correspond donc au bit de poids faible (bit 0) du
  premier octet. Cette règle fixe l’ordre des bits dans chaque octet, sans
  supposer d’ordre des octets pour une valeur multi-octet.
- **Slot `i`** : occupe les octets `[8192 + i×65536, 8192 + (i+1)×65536)`.
- Fichier créé **sparse** (trous logiques non alloués physiquement) : la
  taille sur disque réelle (`du`) reste proportionnelle aux slots
  effectivement écrits, pas à la taille logique de 4 GiO. La plupart des
  systèmes de fichiers modernes (ext4, XFS, ZFS, APFS) supportent nativement
  les fichiers creux et le hole-punching (`fallocate(FALLOC_FL_PUNCH_HOLE)`
  ou équivalent plateforme).

## Nommage et rangement

```
<VolumeConfig.mount_path>/blocks/<owner_type>/<hex(owner_id)>/container-<sequence_number>.bin
```

`sequence_number` (0, 1, 2, …) distingue les conteneurs successifs d'un même
propriétaire lorsque le premier est plein. `VolumeConfig.mount_path` est
celui du volume désigné par `ContainerFile.volume_id` — un Nœud peut
déclarer plusieurs volumes ([`node.NodeConfig`](../02-schemas/node/NodeConfig.md),
champ `volumes: [VolumeConfig]`), et rien d'autre dans `ContainerFile` ne
permet de savoir lequel sans ce champ explicite.

## Sélection du volume à la création d'un conteneur {: #selection-du-volume-a-la-creation-dun-conteneur }

Lorsqu'un nouveau `ContainerFile` doit être créé pour un propriétaire
(aucun trou disponible dans ses conteneurs existants, voir l'algorithme
d'écriture ci-dessous), le Nœud choisit, parmi ses
[`node.VolumeConfig`](../02-schemas/node/VolumeConfig.md) déclarés, celui
disposant du plus d'espace libre restant (`max_capacity_bytes` moins
l'espace physiquement occupé par les conteneurs déjà placés dessus) — une
politique simple de type *least-loaded*, suffisante tant qu'aucune
contrainte de performance différenciée entre volumes (SSD vs HDD, par
exemple) n'est requise.

Aucune garantie qu'un même propriétaire ait tous ses conteneurs sur un seul
volume : un propriétaire volumineux peut parfaitement se retrouver réparti
sur plusieurs volumes physiques au fil du temps, chaque `ContainerFile`
portant son propre `volume_id` indépendamment des autres conteneurs du même
propriétaire. La suppression en masse
([`securite.blacklist-fraude`](../05-securite/blacklist-fraude.md#rupture-bilaterale-immediate))
reste correcte dans ce cas : elle itère sur tous les `ContainerFile` du
propriétaire, quel que soit leur volume.

## Écriture d'un bloc

1. Consulter, pour le propriétaire concerné, la liste de ses
   [`node.ContainerFile`](../02-schemas/node/ContainerFile.md) triés par
   `sequence_number`.
2. Scanner leurs `occupied_bitmap` (en mémoire, mis en cache) pour trouver
   le **premier slot libre** (premier conteneur, plus petit index).
3. **Slot libre trouvé** → écrire le bloc à cet emplacement, positionner le
   bit du bitmap à `1`, enregistrer/mettre à jour l'entrée
   [`node.BlockLocation`](../02-schemas/node/BlockLocation.md) correspondante
   dans le cache local (§3.5).
4. **Aucun slot libre** (tous les conteneurs de ce propriétaire sont pleins,
   ou aucun conteneur n'existe encore) → créer un nouveau
   `ContainerFile` (`sequence_number` = max + 1, bitmap à zéro), écrire au
   slot 0.
5. La mutation (`ContainerFile` modifié ou créé) suit le même cycle
   append-only → compaction déjà en place pour tout `NodeManifest` (voir
   [`node.MutationLog`](../02-schemas/node/MutationLog.md)) — aucun nouveau
   mécanisme de persistance à inventer.

!!! note "Cas des blocs de padding (§4.1)"
    Un bloc de padding (`is_padding=true`,
    [`protocols.erasure-coding`](erasure-coding.md#assemblage-progressif))
    occupe un slot normalement. Son remplacement ultérieur par le vrai bloc
    **réutilise le même `(container_id, slot_index)`** — une simple
    réécriture du contenu chiffré à l'emplacement existant, sans passer par
    un cycle trou + réallocation.

## Suppression d'un bloc {: #suppression-dun-bloc }

Déclenchée par un tombstone confirmé
([`protocols.tombstones`](tombstones.md)) :

1. Positionner le bit du bitmap à `0` (le slot redevient un trou).
2. `fallocate(PUNCH_HOLE)` sur la plage d'octets correspondante — l'espace
   disque est **récupéré immédiatement**, pas seulement marqué libre.
3. Supprimer l'entrée [`node.BlockLocation`](../02-schemas/node/BlockLocation.md)
   du cache local.
4. Le trou devient candidat à la réutilisation dès la prochaine écriture
   pour ce même propriétaire (étape 2 de l'algorithme d'écriture ci-dessus).

## Suppression en masse — le bénéfice central de la segmentation par propriétaire {: #suppression-en-masse }

Si, après une suppression, `occupied_bitmap` d'un conteneur devient
entièrement à zéro, le fichier peut être **supprimé du disque
immédiatement** (et l'entrée `ContainerFile` retirée) plutôt que laissé vide.

Plus important : cette segmentation stricte par propriétaire rend la
**rupture bilatérale immédiate** d'un partenaire fraudeur
([`securite.blacklist-fraude`](../05-securite/blacklist-fraude.md#rupture-bilaterale-immediate))
et le départ d'un utilisateur (migration,
[`protocols.migration-noeud`](migration-noeud.md)) triviaux à exécuter
physiquement : au lieu de devoir scanner et libérer individuellement chaque
bloc dans un stockage partagé, il suffit de **supprimer en bloc les
`ContainerFile` de ce propriétaire** — une opération en O(nombre de
conteneurs), pas en O(nombre de blocs). Pour un partenaire hébergeant 1 TiO
de parité, cela représente ~256 fichiers à supprimer plutôt que ~16 millions
de blocs individuels à localiser puis effacer un par un.

## Restauration (disaster recovery) {: #restauration-disaster-recovery }

L'état des conteneurs (`ContainerFile`, bitmaps inclus) fait partie de la
base SQLite/LMDB locale du Nœud, elle-même incluse dans le snapshot
d'auto-archivage périodique
([`node.MutationLog`](../02-schemas/node/MutationLog.md), §3.10) et donc
récupérable via la procédure standard de
[`deploiement.disaster-recovery`](../07-deploiement/disaster-recovery.md) —
aucun mécanisme de restauration séparé n'est nécessaire. Les entrées fines
[`node.BlockLocation`](../02-schemas/node/BlockLocation.md), elles, peuvent
au besoin être reconstruites par un scan des fichiers conteneurs restaurés
(lecture des bitmaps + recalcul de `block_hash` par slot occupé), en secours
si le cache local rapide n'a pas survécu intact.

## Compaction — hors périmètre de cette version

Un conteneur partiellement vidé (quelques trous, pas entièrement libre)
n'est **pas** automatiquement compacté ou fusionné avec un autre conteneur
sous-utilisé du même propriétaire — cela nécessiterait une réécriture
active, coûteuse. Une tâche de fond de compaction périodique et
non-bloquante pourrait consolider de tels conteneurs à l'avenir ; laissée
hors périmètre de cette version, à l'instar des scénarios de chaos
engineering mentionnés en [`secours.reference-consolidee`](../06-procedures-secours/reference-consolidee.md).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
