---
id: protocols.acces-applicatif
kind: narrative
title: "Accès Applicatif — Lecteur Monté WebDAV"
section: "§3.12"
status: draft
verified_by: []
---

# Accès Applicatif — Lecteur Monté (WebDAV) & Récupération Paresseuse

Le Connecteur expose les données de l'utilisateur sous forme d'un lecteur
réseau mappé/monté via WebDAV, permettant une navigation standard dans un
explorateur de fichiers.

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

## Chemin de secours (reconstruction, lecture seule)

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
