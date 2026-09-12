---
id: securite.integrite-autoreparation
kind: narrative
title: "Intégrité des Blocs Locaux & Auto-réparation"
section: "§5.4"
status: draft
verified_by: []
---

# Intégrité des Blocs de Données Locaux & Auto-réparation

Le Nœud étant l'unique dépositaire des k blocs de données en clair-chiffré,
rien ne garantit nativement qu'il ne serve pas un jour un bloc corrompu
(bit-rot, bug, compromission) sans qu'aucun PoS ne le détecte — le PoS
([`securite.pos-challenges`](pos-challenges.md)) ne porte que sur les blocs
de parité chez les partenaires.

## Détection côté Connecteur

À chaque bloc reçu en fonctionnement normal
([`protocols.acces-applicatif`](../04-protocols/acces-applicatif.md)), le
Connecteur recalcule son hash et le compare au `block_hash` attendu. En cas
d'incohérence, une erreur critique est affichée immédiatement — détail
complet du parcours dans
[`protocols.integrite-lecture`](../04-protocols/integrite-lecture.md).

## Reconstruction automatique

En parallèle de l'alerte, le Connecteur déclenche pour ce bloc précis le
même mécanisme que le chemin de secours — **même si le Nœud reste par
ailleurs joignable** : ce n'est plus une indisponibilité du Nœud qui
déclenche la reconstruction, mais une incohérence d'intégrité détectée sur
un bloc précis.

## Auto-réparation

Une fois le bloc reconstruit et vérifié, le Connecteur le retransmet au
Nœud pour qu'il remplace sa copie locale corrompue — le Nœud agit comme un
simple exécutant.

## Scrubbing proactif côté Nœud

Indépendamment de toute détection Connecteur, le Nœud vérifie
périodiquement l'intégrité de sa copie locale en recalculant les hash et en
les comparant à ceux du
[`dispersal.DispersalManifest`](../02-schemas/dispersal/DispersalManifest.md)
— à la manière d'un scrubbing RAID/ZFS. Réduit la probabilité que
l'utilisateur rencontre lui-même l'erreur critique. Des anomalies répétées
sur un même volume sont un signal de défaillance matérielle, remonté sur le
dashboard ([`deploiement.packaging`](../07-deploiement/packaging.md)).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
