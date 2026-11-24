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
Seuil retenu à l'implémentation (2026-11-19) : un volume est signalé à
partir de **3 anomalies** lors d'un même passage. Le Nœud vérifie que le
bloc renvoyé par le Connecteur correspond à son `block_hash` avant de
remplacer sa copie.

## Auto-réparation par le Nœud seul

Ajout du 2026-11-20 (`impl/SPEC_GAPS.md`) : lors du scrubbing (quotidien
par défaut), un bloc local absent ou altéré est aussi reconstruit par le
Nœud lui-même à partir de k fragments (blocs locaux sains et parité
récupérée chez les partenaires, dont le hash est vérifié), puis réécrit —
sans attendre qu'un Connecteur le relise.

## Perte d'un volume : maintenance automatique {: #maintenance }

Ajout du 2026-11-24. À chaque cycle d'entretien (30 s), le Nœud vérifie
que le fichier de chacun de ses conteneurs
([`protocols.stockage-physique`](../04-protocols/stockage-physique.md))
existe encore. Des fichiers disparus (dossier d'un volume supprimé, disque
remplacé à vide) font passer le Nœud **en maintenance**, état conservé sur
disque :

1. Les conteneurs disparus sont oubliés, le volume reste en service et son
   dossier est recréé ; les fragments perdus sont retirés du solde de
   chaque partenaire ([`node.PartnerAccount`](../02-schemas/node/PartnerAccount.md)),
   les dépôts d'urgence perdus sont oubliés.
2. Les Utilisateurs sont prévenus par un message `Info`
   ([`protocols.canal-noeud`](../04-protocols/canal-noeud.md)) ; leurs
   lectures continuent, un bloc encore absent étant reconstruit par le
   Connecteur lui-même ([`protocols.integrite-lecture`](../04-protocols/integrite-lecture.md)).
3. Le scrubbing est lancé à chaque cycle, sans attendre sa période : chaque
   bloc perdu est reconstruit depuis la parité (§ Auto-réparation par le
   Nœud seul).
4. Envers les partenaires, le Nœud refuse tout `StoreFragment` et répond
   `Maintenance` (au lieu de `NotFound`) à un `Challenge` ou un
   `FetchFragment` sur un fragment perdu
   ([`network.BlockResponse`](../02-schemas/network/BlockResponse.md)).
   Le partenaire replace ce fragment ailleurs **sans compter de
   manquement** ([`node.PartnerAccount#manquements`](../02-schemas/node/PartnerAccount.md#manquements)) :
   la perte est déclarée, pas dissimulée.

La maintenance prend fin quand un passage n'a plus rien à reconstruire, ou
après 10 passages (environ 5 minutes) ; les Utilisateurs reçoivent alors un
second message, avec le nombre de blocs irrécupérables le cas échéant —
ceux qui n'étaient pas encore dispersés au moment de la perte, que seul un
appareil ayant encore le fichier peut renvoyer. Le dashboard affiche l'état
et la progression (section « Maintenance » de la vue d'ensemble).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
