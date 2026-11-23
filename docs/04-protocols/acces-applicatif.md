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
d'installation : WinFsp ou FUSE, sauf en [mode dossier](#mode-dossier)
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

## Mode dossier (sans pilote) {: #mode-dossier }

Ajout du 2026-11-22. Installer WinFsp demande un compte administrateur. Sans
lui, le Connecteur expose les fichiers dans un **dossier synchronisé** du
système, sans pilote ni droit d'administration : **Cloud Files** sous
Windows 10 1709 et plus (volume NTFS), **File Provider** sous macOS (plus
tard ; extension d'application signée). Linux n'en a pas besoin : FUSE y
monte sans être root.

- **Choix** : réglage « accès aux fichiers » = `lecteur` (lettre, WinFsp)
  ou `dossier`. L'assistant propose `dossier` par défaut, même si WinFsp
  est installé (2026-11-23) ; le Connecteur le prend d'office si WinFsp
  est absent.
  Emplacement par défaut : `%USERPROFILE%\S3m`.
- **Fantômes** : chaque fichier et dossier y apparaît comme un fantôme
  (taille et dates, aucun contenu). Le contenu d'un dossier est fourni à sa
  première ouverture, celui d'un fichier à sa première lecture, par les
  mêmes lectures que le lecteur monté : la récupération reste
  [paresseuse](#recuperation-paresseuse-lazy). Un fichier lu reste disponible
  hors ligne jusqu'à « Libérer de l'espace ».
- **Libérer de l'espace** (2026-11-23, tableau de bord, page Fichiers) :
  le contenu des fichiers à jour (déjà chez le Nœud) est retiré du disque,
  pour tout le dossier ou un sous-dossier ; ils redeviennent des fantômes,
  rien n'est supprimé. Un fichier pas encore envoyé n'est jamais touché.
  **Libération automatique** réglable (`free_after_days`, 0 : jamais) :
  chaque heure, fichiers ni ouverts ni téléchargés depuis ce nombre de
  jours. Les dates d'un fichier étant celles de son auteur, le Connecteur
  note l'instant de chaque téléchargement (`telechargements.json` dans les
  données de l'identité).
- **Modifications locales** : écrites par l'application dans le vrai
  fichier. Le Connecteur les détecte, attend 2 s sans nouvelle écriture,
  relit le fichier et n'enregistre que les blocs de 64 Kio qui diffèrent,
  puis le marque synchronisé ; la suite est celle de
  [`protocols.ecriture-differee`](ecriture-differee.md). Créations,
  suppressions et renommages suivent le même chemin.
- **Modifications distantes** (autre appareil) : dans les dossiers déjà
  ouverts, les fantômes sont créés, supprimés ou remplacés ; un fichier
  modifié localement et pas encore enregistré n'est pas remplacé.
- **Limite** : un fichier lu est conservé en clair dans le profil de
  l'utilisateur, comme la copie locale du lecteur monté.

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
