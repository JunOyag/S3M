---
id: network.vdf-verifier-pure
kind: narrative
title: "Instrumentation et fixtures VDF"
section: "§2.1"
status: draft
verified_by: []
---

# Instrumentation et fixtures VDF

Cette page fixe ce qui accompagne le VDF d'identité de
[`network.vdf-identity`](vdf-identity.md) côté tests et mesures. Elle ne
définit **aucune** implémentation de vérification : `chiavdf` est le seul
prouveur et le seul vérificateur du protocole, lié en natif par le Nœud et
par le Connecteur (tous deux en Rust).

!!! note "Révision V3 (2026-11-19)"
    La V2 de cette page spécifiait un vérificateur Wesolowski en Rust pur,
    exécutable en natif et en WASM, pour un Connecteur TypeScript qui ne
    pouvait pas lier `chiavdf`. Le Connecteur étant désormais un binaire
    Rust natif, ce besoin disparaît : le vérificateur maison est **retiré**
    (il contredisait la règle « lier `chiavdf`, jamais de code VDF maison »
    d'`impl/TECH_STACK.md`), ainsi que le harnais WASM. Le Connecteur
    embarque de toute façon `chiavdf` pour **générer** la preuve de
    l'identité User.

## Fixtures à `T = 100`

Les tests rapides ne peuvent pas rejouer `T = 5 400 000`. Ils s'appuient sur
des **fixtures générées une fois** avec `chiavdf` puis versionnées :

- `T = 100`, `recursion = 0`, λ = 1024 ;
- identité marquée **valide pour la V3** : tag `key_algorithm = 0`
  (`0x00 ‖ clé publique de 32 o`, voir
  [`network.vdf-identity`](vdf-identity.md#identite-marquee)) ;
- chaque fixture est accompagnée de sa **provenance** : version de
  `chiavdf`, plateforme et commande de génération ; une fixture sans
  provenance n'est pas acceptée.

Les fixtures de la V2 (identité `0x07 ‖ [0x31; 32]`, tag désormais rejeté)
sont à régénérer.

## Critères de conformité

La tâche est close sur quatre critères :

1. **Natif** : la fixture est acceptée par `verify_n_wesolowski` avec ses
   paramètres.
2. **Accord** : la sortie de `chiavdf::prove` régénérée en CI est identique
   octet pour octet à la fixture versionnée.
3. **Rejets** : un octet altéré de `y`, de `π` ou de l'identité (tag ou clé)
   fait échouer la vérification ; un `T` différent aussi.
4. **Traçabilité** : la provenance de chaque fixture est versionnée à côté
   d'elle.

## Instrumentation par phase

Pour décider si la dérivation de `Δ` domine le coût de vérification (V3
§2.1, « Coût côté vérificateur »), chaque phase est mesurée séparément là où
l'API de `chiavdf` le permet :

| Phase | Mesure |
|---|---|
| Dérivation de `Δ` (`create_discriminant`) | séparée |
| Mise en groupe et évaluation séquentielle | combinées dans `prove` (non séparables depuis l'API publique) |
| Génération de la preuve | combinée dans `prove` |
| Vérification (`verify_n_wesolowski`) | séparée, recalcul de `Δ` compris |

Mesures de référence du run CI du 19/10/2026 (`T = 100`, avant retrait du
vérificateur pur) : `create_discriminant` 9 à 44 ms, `prove` 15 à 35 ms,
vérification `chiavdf` 4,6 à 6,4 ms.

## Cible `wasm32`

Aucune exigence : `impl/core` n'a plus de consommateur WASM. Une
vérification de compilation `wasm32` peut subsister en CI à titre non
bloquant, sans harnais d'exécution.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
