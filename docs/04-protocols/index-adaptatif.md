---
id: protocols.index-adaptatif
kind: narrative
title: "Arbre d'Index Adaptatif"
section: "§3.6"
status: draft
verified_by: []
---

# Arbre d'Index Adaptatif

Pour 1 TiO de données initiales (ratio 4x, voir
[`overview.architecture`](../00-overview/architecture.md)), il faut adresser
environ 2²⁶ ≈ 67 millions de blocs, soit ~4,19 millions de stripes (k=4). Une
structure plate est insuffisante de plusieurs ordres de grandeur — d'où
l'arbre adaptatif.

## Estimation de capacité

- [`dispersal.BlockEntry`](../02-schemas/dispersal/BlockEntry.md) sérialisé :
  ≈ **48 octets**.
- [`dispersal.Stripe`](../02-schemas/dispersal/Stripe.md) complète (N=16 pour
  k=4, coef=3) : ≈ **810 octets**.
- Un bloc de 64 KiO contient donc, avec marge de sécurité :
  **≤ 75 stripes par [`dispersal.IndexNode`](../02-schemas/dispersal/IndexNode.md)**.

Avec ce facteur de branchement F=75 : 4,19M stripes / 75 ≈ 55 867 blocs
feuilles ; / 75 ≈ 745 blocs de niveau 1 ; / 75 ≈ 10 blocs de niveau 2, qui
tiennent dans une seule racine. **3 niveaux d'indirection suffisent** pour
1 TiO par utilisateur, avec marge confortable au-delà.

## Croissance adaptative

Le [`dispersal.DispersalManifest`](../02-schemas/dispersal/DispersalManifest.md)
organise son catalogue en arbre — à petite échelle les `Stripe` sont
stockées directement à la racine ; au-delà de sa capacité, un niveau
d'indirection est ajouté, et ainsi de suite. **La profondeur ne grandit que
si nécessaire** (pas de profondeur fixe pré-allouée).

Chaque enfant de l'arbre est lui-même un `Stripe` complet (k fragments de
données + coef×k fragments de parité), pas un pointeur unique — la perte
d'un partenaire ne casse donc jamais un sous-arbre entier. Chiffrement de
chaque `IndexNode` enfant : voir
[`crypto.k-dispersal`](../03-crypto/k-dispersal.md).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
