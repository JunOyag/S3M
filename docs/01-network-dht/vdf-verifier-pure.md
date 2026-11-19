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

## Fixtures à `T = 1000`

Les tests rapides ne peuvent pas rejouer `T = 5 400 000`. Ils s'appuient sur
des **fixtures générées une fois** avec `chiavdf` puis versionnées :

- `T = 1000`, `recursion = 0`, λ = 1024 ;
- identité marquée **valide pour la V3** : tag `key_algorithm = 0`
  (`0x00 ‖ clé publique de 32 o`, voir
  [`network.vdf-identity`](vdf-identity.md#identite-marquee)) ;
- chaque fixture est accompagnée de sa **provenance** : version de
  `chiavdf`, plateforme et commande de génération ; une fixture sans
  provenance n'est pas acceptée.

!!! warning "Pourquoi pas `T = 100`"
    La preuve vaut `π = g^⌊2^T/ℓ⌋`, où `ℓ` est un premier d'environ 264 bits
    dérivé par `chiavdf`. Pour `T < 264`, `⌊2^T/ℓ⌋ = 0` : `π` ne porte
    aucune information, et `chiavdf` accepte alors **n'importe quels**
    octets de `π` (constaté le 2026-11-19 sur les 200 positions × 2 bits).
    Une fixture à `T = 100` ne peut donc pas tester le rejet d'un `π`
    altéré. Dès `T = 1000`, toute altération de `π` est rejetée. Le `T` de
    protocole (5 400 000) n'est pas concerné.

Fixture versionnée : `impl/core/tests/fixtures/vdf_identity_tag0_t1000.hex`
(identité `0x00 ‖ [0x31; 32]`) et sa provenance (`.provenance`). Les
fixtures de la V2 (`T = 100`, tag `0x07` désormais rejeté) sont retirées.

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

Mesures : run CI du 19/10/2026 (`T = 100`) — `create_discriminant` 9 à
44 ms, `prove` 15 à 35 ms, vérification 4,6 à 6,4 ms ; Docker
`rust:1-bookworm` x86_64 du 2026-11-19 (`T = 1000`) — `prove` 11 ms,
vérification 6 ms (test `vdf_fixtures::phase_timings_are_reported`).

## Cible `wasm32`

Aucune exigence : `impl/core` n'a plus de consommateur WASM. Une
vérification de compilation `wasm32` peut subsister en CI à titre non
bloquant, sans harnais d'exécution.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
