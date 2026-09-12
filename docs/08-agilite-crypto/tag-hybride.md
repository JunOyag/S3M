---
id: agilite.tag-hybride
kind: narrative
title: "Tag d'Algorithme & Mode Hybride"
section: "§8.4"
status: draft
verified_by: []
---

# Tag d'Algorithme & Mode Hybride

## `key_algorithm` {: #key_algorithm }

Chaque clé publique asymétrique (Node, User, recovery) porte un
`key_algorithm: uint8` (0 = Ed25519/X25519 — schéma de référence, 1 =
ML-DSA/ML-KEM, 2 = hybride) permettant à tout vérificateur de savoir quel
schéma appliquer. Champ additif, cohérent avec la règle d'évolution de
schéma — voir [`node.AttachedUser`](../02-schemas/node/AttachedUser.md).

Le VDF ([`network.vdf-identity`](../01-network-dht/vdf-identity.md)) n'est
pas affecté par ce choix : `H(pub_key)` reste valide quel que soit
l'algorithme, tant que `pub_key` inclut son tag.

## Mode hybride

Pendant une période de transition, un mode hybride est recommandé :
combiner les deux secrets (`KDF(X25519(...) || ML-KEM_secret, salt)`)
plutôt qu'une bascule sèche, en défense en profondeur si une faiblesse
était découverte dans l'un des deux schémas.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
