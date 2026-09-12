---
id: deploiement.packaging
kind: narrative
title: "Packaging & Interface (Dashboards)"
section: "§7.3"
status: draft
verified_by: []
---

# Packaging & Interface

Deux applications Web locales distinctes (`http://localhost:xxxx`) — l'une
pour le **Nœud**, l'autre pour le **Connecteur**.

## Dashboard Nœud

Volumes et quotas ([`node.NodeConfig`](../02-schemas/node/NodeConfig.md)),
utilisateurs rattachés
([`node.AttachedUser`](../02-schemas/node/AttachedUser.md)), état des
partenaires ([`node.PartnerAccount`](../02-schemas/node/PartnerAccount.md),
dernière PoS réussie, purge à venir), liste noire
([`securite.blacklist-fraude`](../05-securite/blacklist-fraude.md)), taux
de republication DHT
([`network.dht-directory`](../01-network-dht/dht-directory.md)), alertes de
scrubbing/auto-réparation
([`securite.integrite-autoreparation`](../05-securite/integrite-autoreparation.md)),
espace de secours occupé/réservé pour tiers en détresse
([`protocols.espace-secours`](../04-protocols/espace-secours.md)).

## Dashboard Connecteur

Nœud rattaché et son état de joignabilité, palier d'alerte de migration en
cours (ancienneté de `inactivity_detected_at`), état de la
[`protocols.write-queue`](../04-protocols/write-queue.md) (mutations en
attente, taille, dernière synchronisation, entrées rejetées pour
dépassement de quota — [`protocols.quota-sync`](../04-protocols/quota-sync.md)),
état de l'écriture d'urgence
([`protocols.espace-secours`](../04-protocols/espace-secours.md) —
partenaires utilisés, estimation du quota consommé par les autres
Connecteurs), historique des incidents d'intégrité
([`protocols.integrite-lecture`](../04-protocols/integrite-lecture.md)),
configuration de `Q_max` (4 GiO par défaut) et de l'intervalle de
surveillance (5 minutes par défaut).

## Déploiement

- **Nœud** : image conteneurisée officielle Docker (et binaire autonome),
  NAS/serveurs domestiques/Raspberry Pi.
- **Connecteur** : exécutable portable, indépendant du Nœud, généré avec
  Bun.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
