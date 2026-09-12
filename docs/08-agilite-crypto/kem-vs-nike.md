---
id: agilite.kem-vs-nike
kind: narrative
title: "Contrainte Structurelle : un KEM n'est pas un NIKE"
section: "§8.1"
status: draft
verified_by: []
---

# Contrainte Structurelle : un KEM n'est pas un NIKE

Cette section anticipe une bascule future des primitives asymétriques
(Ed25519/X25519) vers des schémas post-quantiques standardisés (ML-DSA pour
la signature, ML-KEM pour l'échange de clé). Elle ne remplace pas le schéma
de référence (Ed25519/X25519) mais documente comment y migrer sans rupture.

## X25519 est un NIKE

Les deux parties calculent le même secret **indépendamment**, sans jamais
rien s'échanger — propriété directement exploitée par
[`crypto.k-attach`](../03-crypto/k-attach.md) (*« aucun secret n'est jamais
transmis »*) et par la reconstruction locale côté Nœud.

## ML-KEM est un KEM

Structurellement asymétrique : l'Initiator encapsule un secret avec la clé
publique du Responder et obtient `(shared_secret, kem_ciphertext)` ; le
Responder doit **recevoir** `kem_ciphertext` pour décapsuler. Aucun KEM
post-quantique standardisé ne reproduit le calcul « chacun de son côté » de
X25519 — c'est une contrainte du problème mathématique sous-jacent (réseaux
euclidiens), pas un détail d'implémentation contournable.

Voir [`agilite.k-attach-kem`](k-attach-kem.md) pour le redesign de
`K_attach` qui en découle.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
