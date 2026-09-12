---
id: overview.architecture
kind: narrative
title: "Vue d'ensemble & Architecture Globale"
section: "§1"
status: draft
verified_by: []
---

# Vue d'ensemble & Architecture Globale

Réseau de stockage pair-à-pair (P2P) souverain, décentralisé et hautement
disponible, reposant sur un modèle d'échange équitable de ressources (1:1)
entre nœuds partenaires, sans organe centralisé de contrôle.

## Principes clés

- **Architecture réseau** : `libp2p` (NAT natif, relais STUN/TURN/ICE, DHT
  Kademlia) — détaillé dans [`network.dht-directory`](../01-network-dht/dht-directory.md).
- **Unité de stockage (bloc)** : taille fixe 64 KiO (65 536 octets), chiffré
  de bout en bout, en-tête fixe (version de protocole).
- **Équité d'échange (Troc 1:1)** : chaque bloc de parité envoyé sur un nœud
  distant consomme un quota équivalent local. Comptabilité détaillée dans
  [`node.PartnerAccount`](../02-schemas/node/PartnerAccount.md).
- **Redondance Reed-Solomon** : k blocs de données → coef×k blocs de parité
  (coef=3 par défaut) → N = k + coef×k blocs par stripe. Voir
  [`protocols.erasure-coding`](../04-protocols/erasure-coding.md) pour la
  mécanique complète, et [`dispersal.Stripe`](../02-schemas/dispersal/Stripe.md)
  pour la structure.
- **Empreinte disque** : ratio global 4x — 1 copie locale intégrale des k
  blocs de données (jamais dispersée) + 3x le volume utile en blocs de
  parité distribués.
- **Sécurité des identités** : VDF de Wesolowski anti-Sybil, coût
  physiquement séquentiel (~1 min). Voir
  [`network.vdf-identity`](../01-network-dht/vdf-identity.md).

## Ce que cette page ne couvre pas

Le détail de chaque mécanisme cité ci-dessus vit dans sa propre page — cette
page reste volontairement une **table des matières commentée**, pour éviter
de dupliquer un contenu déjà rédigé ailleurs.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build — voir `gen_docs.py`)*

<!-- GENERATED:BACKLINKS:END -->
