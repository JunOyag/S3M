---
id: network.vdf-identity
kind: narrative
title: "VDF de Wesolowski — Identités anti-Sybil"
section: "§2.1"
status: draft
verified_by: []
---

# VDF de Wesolowski — Identités anti-Sybil

Contrairement à une Proof of Work classique (parallélisable — un attaquant
disposant de N machines peut produire N identités dans le même temps
physique qu'une seule machine), la génération d'une nouvelle identité (Node
ou User) repose sur une **Fonction à Délai Vérifiable (VDF)**, dont la
séquentialité est prouvée : aucune quantité de matériel parallèle ne permet
d'en réduire le temps de calcul.

## Setup — un discriminant `Δ` global, pas un module par identité

Le groupe utilisé est la classe de formes quadratiques imaginaires `Cl(Δ)`
pour un discriminant `Δ` **négatif, fixé une fois pour toutes au niveau du
protocole**. Contrairement à un groupe RSA (module `N = p·q` nécessitant une
cérémonie MPC pour garantir que sa factorisation reste inconnue), l'ordre de
`Cl(Δ)` est structurellement inconnu de quiconque dès lors que `Δ` est
choisi de façon vérifiable et non malléable — **pas de cérémonie de
confiance requise**.

`Δ` est dérivé publiquement par une procédure « rien dans la manche » :
recherche du plus petit nombre premier `p > 2^λ` (λ = 2048 bits) tel que
`p ≡ 3 mod 4`, en partant du hash d'une chaîne fixe publique et en
incrémentant jusqu'à trouver un candidat premier. `Δ = -p`. N'importe qui
peut rejouer cette recherche et vérifier qu'aucun choix arbitraire n'a
permis d'introduire une trappe.

## Calcul séquentiel & preuve

- Le challenge `x = H(pub_key)` est mappé en une forme quadratique
  `g ∈ Cl(Δ)`, puis `y = g^(2^T)` est calculé par `T` mises au carré
  successives (algorithme NUDUPL) — chaque étape dépendant strictement de la
  précédente, ~1 minute sur une machine de référence.
- **Preuve de Wesolowski** : une preuve courte `π = g^⌊2^T/ℓ⌋` permet à tout
  pair DHT de vérifier `y = π^ℓ · g^r` en temps logarithmique, sans rejouer
  les T mises au carré. Coût de génération élevé et incompressible ; coût de
  vérification négligeable.
- Seul `(pub_key, y, π)` est joint à toute nouvelle entrée DHT — `Δ`, `T` et
  la procédure de mise en groupe sont fixés une fois par la spécification,
  implicites pour tout vérificateur.

## Limite connue

Ce coût dissuade la génération massive et parallèle d'identités, mais
n'empêche pas, en théorie, une régénération après le délai minimal
(~1 min). Pertinent notamment pour le contournement de la liste noire — voir
[`securite.blacklist-fraude`](../05-securite/blacklist-fraude.md#note-de-conception).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
