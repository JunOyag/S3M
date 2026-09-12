---
id: protocols.write-queue
kind: narrative
title: "Écriture Hors-Ligne — WriteQueue"
section: "§3.12.2"
status: draft
verified_by: []
---

# Écriture Hors-Ligne — File d'Attente Locale (`WriteQueue`)

Permet l'écriture (création, modification, suppression) même Nœud
injoignable — coupure réseau **totale** du Connecteur. Voir
[`fs.WriteQueue`](../02-schemas/fs/WriteQueue.md) pour la structure.

## Mécanisme

- **Écriture mise en file** : les nouveaux blocs sont chiffrés
  ([`crypto.k-block`](../03-crypto/k-block.md)) comme en fonctionnement
  normal et stockés temporairement en local ; la mutation FS correspondante
  est journalisée, horodatée, **sans** modifier `fs_root_hash`.
- **Lecture pendant la panne** : vue fusionnant le `UserManifest` local et
  la `WriteQueue` en attente.
- **Synchronisation au retour** : rejeu **strictement dans l'ordre
  d'horodatage** (upload des blocs, puis mutations FS). **Contrainte
  d'ordre impérative** : tous les `write_block` d'une chaîne doivent être
  confirmés avant que le `update_entry` qui les référence ne soit rejoué —
  aucune parallélisation ni réordonnancement autorisé, sous peine de
  pointeur orphelin.

## Résolution de conflit (multi-appareils) {: #resolution-de-conflit }

Le Nœud ne voit que des blocs opaques — il ne peut ni comparer leur
contenu, ni identifier quel fichier a changé. La détection est donc
**entièrement à la charge du Connecteur** : au moment de mettre en file, il
note `base_fs_root_hash` (voir
[`fs.WriteQueue`](../02-schemas/fs/WriteQueue.md)) ; à la synchronisation,
il compare au `fs_root_hash` réel. Une différence signale qu'un autre
appareil a écrit entre-temps. Résolution par **dernier écrit gagne**
(comparaison des `modified_at`,
[`fs.Attributes`](../02-schemas/fs/Attributes.md)) au niveau de chaque
élément concerné — le fichier perdant est conservé hors arborescence
(suffixe de conflit) plutôt que silencieusement écrasé.

## Taille limite

`Q_max = 4 GiO` par défaut, paramétrable via le dashboard Connecteur. Ce
budget est **partagé** avec
[`protocols.espace-secours`](espace-secours.md) — seule la stratégie de
dispersion diffère selon la connectivité disponible.

## Gestion du quota multi-Connecteurs

Voir [`protocols.quota-sync`](quota-sync.md) pour le cas où plusieurs
Connecteurs du même Utilisateur écrivent hors-ligne en parallèle.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
