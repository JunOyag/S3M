---
id: protocols.volatilite-reparation
kind: narrative
title: "Gestion de la Volatilité & Sur-redondance"
section: "§4.2"
status: draft
verified_by: []
---

# Gestion de la Volatilité & Sur-redondance

Analyse quotidienne de la disponibilité des partenaires hébergeant les
coef×k fragments de parité — les k blocs de données locaux ne sont, par
construction, jamais concernés (seul un incident sur le nœud hébergeur
lui-même les affecterait, voir
[`protocols.erasure-coding`](erasure-coding.md)).

## Réparation préventive

Si le nombre de fragments de parité disponibles descend vers le seuil
minimal k, le nœud reconstruit le stripe localement (à partir de sa copie
des k blocs de données, voir
[`securite.pos-challenges`](../05-securite/pos-challenges.md#calcul-du-challenge))
et réémet les fragments manquants vers de nouveaux partenaires.

## Résolution du surplus

Si un nœud réapparaît avant la purge, la sur-redondance est résorbée et les
blocs temporaires sont supprimés.

Ce parcours s'applique aux **absences simples** (timeout/indisponibilité) —
à distinguer du cas de fraude cryptographique avérée, traité dans
[`securite.blacklist-fraude`](../05-securite/blacklist-fraude.md), où la
réparation est déclenchée **immédiatement**, hors cycle quotidien.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
