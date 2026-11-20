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
Seuil retenu à l'implémentation (2026-11-19) : réparation dès que moins de
**k + 2** fragments de parité sont disponibles — même valeur que le seuil de
confirmation de
[`protocols.dispersion-transactionnelle`](dispersion-transactionnelle.md).
Les nouveaux partenaires sont distincts de tous ceux qui hébergent déjà un
fragment de la stripe.

## Résolution du surplus

Si un nœud réapparaît avant la purge, la sur-redondance est résorbée et les
blocs temporaires sont supprimés.

**Orchestration par le Nœud** (2026-11-20, `impl/SPEC_GAPS.md`) : la
disponibilité se mesure par partenaire (dernier challenge PoS réussi, fenêtre
d'un jour par défaut). Le fragment réparé est **définitivement** confié au
nouveau partenaire ; c'est la copie de l'absent qui est purgée par tombstone
quand il redevient joignable (même redondance finale que la suppression des
copies temporaires, sans double comptabilité). Les stripes d'index, sans
copie locale, ne sont pas réparés fragment par fragment : l'arbre est réémis
([`protocols.dispersion-transactionnelle`](dispersion-transactionnelle.md#orchestration)).

Ce parcours s'applique aux **absences simples** (timeout/indisponibilité) —
à distinguer du cas de fraude cryptographique avérée, traité dans
[`securite.blacklist-fraude`](../05-securite/blacklist-fraude.md), où la
réparation est déclenchée **immédiatement**, hors cycle quotidien.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
