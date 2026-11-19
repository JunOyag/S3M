---
id: protocols.acces-applicatif
kind: narrative
title: "Accès Applicatif — Lecteur Monté natif"
section: "§3.12"
status: draft
verified_by: []
---

# Accès Applicatif — Lecteur Monté & Récupération Paresseuse

Le Connecteur expose les données de l'utilisateur sous forme d'un **lecteur
monté natif**, via un pilote de système de fichiers en espace utilisateur,
derrière un **trait de système de fichiers commun** dans le moteur :

- **WinFsp** sous Windows — cible de la première version ;
- **FUSE** sous Linux, puis macOS (macFUSE ou FUSE-T, choix à trancher à ce
  moment) — ajoutés ensuite sans modifier le moteur.

Le moteur n'a qu'une implémentation de la logique de fichiers ; chaque
système fournit son backend. **Aucun service réseau n'est exposé pour
l'accès aux fichiers** (la V2 prévoyait WebDAV, retiré en V3). Prérequis
d'installation : WinFsp ou FUSE — le Connecteur n'est donc plus un
exécutable entièrement autonome
([`deploiement.packaging`](../07-deploiement/packaging.md)).

Les écritures du lecteur se font par plages d'octets sur une copie locale
reconstituée, synchronisée de façon différée — voir
[`protocols.ecriture-differee`](ecriture-differee.md).

## Chemin normal (direct, lecture et écriture)

Les k blocs de données originaux étant toujours conservés en clair-chiffré
sur le nœud hébergeur lui-même, la lecture consiste simplement à demander
directement au Node le bloc correspondant (par `block_hash`) — **aucune
reconstruction Reed-Solomon** ni sollicitation des partenaires n'est
nécessaire. Seul ce chemin permet d'altérer les données de façon durable —
voir [`protocols.fs-structure`](fs-structure.md) pour l'encodage exact.

!!! warning "SPOF en écriture confirmée — compromis assumé"
    Le Nœud reste le seul point de vérité pour une écriture *confirmée et
    dispersée* : sa panne bloque toute confirmation durable, quelle que soit
    la robustesse de la redondance en lecture. La
    [`protocols.write-queue`](write-queue.md) atténue l'impact perçu pendant
    une panne courte, sans supprimer ce compromis structurel du modèle «
    souverain » — l'utilisateur reste libre de changer de Nœud à tout moment
    ([`protocols.migration-noeud`](migration-noeud.md)) si les pannes sont
    trop fréquentes.

## Chemin de secours (reconstruction, lecture seule) {: #chemin-de-secours }

Si le nœud hébergeur est indisponible, le Connecteur peut reconstruire,
pour chaque bloc recherché, les k blocs de la stripe correspondante à
partir de k fragments de parité récupérés directement chez les partenaires
([`protocols.erasure-coding`](erasure-coding.md)), afin d'afficher
l'arborescence et de consulter les fichiers déjà confirmés. Ce chemin reste
**strictement en lecture seule** pour les données déjà dispersées — les
écritures pendant l'indisponibilité passent par
[`protocols.write-queue`](write-queue.md) (coupure totale) ou
[`protocols.espace-secours`](espace-secours.md) (Nœud seul injoignable).

## Vérification d'intégrité

Voir [`protocols.integrite-lecture`](integrite-lecture.md) pour le
mécanisme de recalcul de hash à chaque bloc reçu, et la procédure en cas
d'incohérence.

## Récupération paresseuse (lazy)

Dans les deux cas de lecture, le Connecteur ne résout que les blocs
strictement nécessaires à la portion de l'arborescence effectivement
consultée — sans jamais forcer un parcours ou téléchargement anticipé de
l'intégralité des données, cohérent avec le passage à l'échelle décrit dans
[`protocols.index-adaptatif`](index-adaptatif.md).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
