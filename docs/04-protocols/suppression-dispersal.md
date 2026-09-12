---
id: protocols.suppression-dispersal
kind: narrative
title: "Suppression Explicite d'une Entrée DispersalManifest"
section: "§3.7.2"
status: draft
verified_by: []
---

# Suppression Explicite d'une Entrée DispersalManifest

Au-delà de l'expiration naturelle à 6 mois
([`network.dht-directory`](../01-network-dht/dht-directory.md)), le Nœud
peut supprimer explicitement une entrée par anticipation — typiquement
lorsqu'un Utilisateur le quitte
([`protocols.migration-noeud`](migration-noeud.md)) ou supprime son compte.
Il signe la demande avec `sig_priv_dispersal` et la publie sur la DHT.

## Pourquoi seul le Nœud peut signer une suppression

Contrairement à ce qu'autoriserait la dérivation symétrique de
`sig_priv_dispersal` par le Connecteur
([`crypto.k-attach`](../03-crypto/k-attach.md#portee-de-signature-derivee)),
cette capacité lui est délibérément réservée : permettre au Connecteur de
supprimer unilatéralement l'entrée introduirait un risque de déséquilibre de
troc côté Nœud (perte de la référence à des blocs de parité toujours
effectivement hébergés chez des partenaires, sans que le Nœud n'ait pu
réagir).

Le cas de la mort avérée du Nœud n'a donc plus besoin d'un mécanisme de
suppression signé par le Connecteur : l'entrée expirera d'elle-même dans la
fenêtre de 6 mois, le Nœud disparu cessant naturellement de la republier.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
