---
id: overview.glossary
kind: narrative
title: "Glossaire"
section: "—"
status: draft
verified_by: []
---

# Glossaire

| Terme | Définition courte | Détail |
|---|---|---|
| **Bloc** | Unité de stockage fixe, 64 KiO | [`overview.architecture`](architecture.md) |
| **Stripe** | k blocs de données + coef×k blocs de parité | [`dispersal.Stripe`](../02-schemas/dispersal/Stripe.md) |
| **Nœud / Node** | Hébergeur — conserve la copie locale intégrale des données | [`node.NodeManifest`](../02-schemas/node/NodeManifest.md) |
| **Connecteur** | Client utilisateur, expose un lecteur WebDAV | [`protocols.acces-applicatif`](../04-protocols/acces-applicatif.md) |
| **Partenaire (troc)** | Nœud tiers hébergeant des fragments de parité | [`dispersal.Partner`](../02-schemas/dispersal/Partner.md) |
| **DHT** | Annuaire Kademlia, indexé par Identité | [`network.dht-directory`](../01-network-dht/dht-directory.md) |
| **VDF** | Preuve de délai vérifiable, anti-Sybil | [`network.vdf-identity`](../01-network-dht/vdf-identity.md) |
| **PoS** | Proof of Storage, challenge de possession | [`securite.pos-challenges`](../05-securite/pos-challenges.md) |
| **K_attach** | Clé partagée Nœud↔Connecteur, métadonnées de dispersion | [`crypto.k-attach`](../03-crypto/k-attach.md) |
| **K_block** | Clé propre au User, contenu réel des blocs | [`crypto.k-block`](../03-crypto/k-block.md) |
| **WriteQueue** | File d'écriture locale hors-ligne | [`protocols.write-queue`](../04-protocols/write-queue.md) |
| **EmergencyManifest** | Espace de secours, Nœud seul injoignable | [`protocols.espace-secours`](../04-protocols/espace-secours.md) |
| **Tombstone** | Suppression bilatérale confirmée | [`protocols.tombstones`](../04-protocols/tombstones.md) |
| **Blacklist** | Liste noire locale, rupture de troc définitive | [`securite.blacklist-fraude`](../05-securite/blacklist-fraude.md) |
| **Conteneur (ContainerFile)** | Fichier physique de 4 GiO regroupant les blocs d'un propriétaire | [`protocols.stockage-physique`](../04-protocols/stockage-physique.md) *(ajout post-V2)* |

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
