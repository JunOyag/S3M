---
id: dispersal.Stripe
kind: schema
title: "Stripe"
section: "§3.11"
fbs_source: "schemas/dispersal/DispersalManifest.fbs#Stripe"
status: draft
verified_by: []
---

# Stripe

Un groupe de k blocs de données + coef×k blocs de parité (N = k + coef×k).
Unité de base de l'erasure coding.

## Champs

```
--8<-- "dispersal/Stripe.table.md"
```

`blocks` référence des [`dispersal.BlockEntry`](BlockEntry.md), indices 0 à
k-1 pour les données (toujours locales) et k à N-1 pour la parité
(dispersée). Le détail de l'algorithme de découpage/reconstruction, du
des paramètres fixes (k = 4, coef = 3, N = 16) et de la tolérance aux pannes est
traité dans [`protocols.erasure-coding`](../../04-protocols/erasure-coding.md)
— non répété ici.

## Utilisation en dehors des feuilles

Un `Stripe` n'est pas réservé au contenu utilisateur : chaque enfant de
l'arbre d'index adaptatif est lui-même un `Stripe` complet — voir
[`dispersal.IndexNode`](IndexNode.md) et
[`protocols.index-adaptatif`](../../04-protocols/index-adaptatif.md). C'est
ce qui garantit que la perte d'un partenaire ne casse jamais un sous-arbre
entier, cohérent avec la tolérance aux pannes appliquée aux feuilles.

Dans ce cas — et seulement dans ce cas — `encryption_salt` porte le sel
de 16 octets de l'`IndexNode` enfant, neuf à chaque réémission du nœud,
qui dérive sa clé de bloc `K_dispersal_block`
([`crypto.k-dispersal`](../../03-crypto/k-dispersal.md)). Pour un Stripe
de contenu utilisateur, le champ est vide.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
