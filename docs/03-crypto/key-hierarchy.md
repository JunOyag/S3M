---
id: crypto.key-hierarchy
kind: narrative
title: "Hiérarchie des Clés — Vue d'ensemble"
section: "§3.8"
status: draft
verified_by: []
---

# Hiérarchie des Clés — Vue d'ensemble

Toutes les clés du protocole dérivent, en dernier ressort, d'une seed
BIP-39 (une pour le User, une pour le Node). Le schéma de chemins exact
(BIP-39 → SLIP-0010, rôles User / Node / clé de secours) vit sur
[`crypto.identity-derivation`](identity-derivation.md) ; la procédure de
restauration associée sur
[`deploiement.disaster-recovery`](../07-deploiement/disaster-recovery.md).
Cette page ne fait que pointer vers chaque clé ; le détail de dérivation et
d'usage vit sur sa propre page.

| Clé | Portée | Détail |
|---|---|---|
| Identités (priv_user, priv_node, priv_node_recovery) | Ed25519 dérivées de la seed BIP-39 (SLIP-0010) | [crypto.identity-derivation](identity-derivation.md) |
| `K_attach` | Partagée Nœud↔Connecteur, métadonnées de dispersion | [`crypto.k-attach`](k-attach.md) |
| `K_dispersal_content` / `K_dispersal_block` | Dérivées de `K_attach`, blocs internes de l'arbre d'index | [`crypto.k-dispersal`](k-dispersal.md) |
| `K_block` | Propre au User, contenu réel des blocs | [`crypto.k-block`](k-block.md) |
| `K_node_self` | Propre au Nœud, confidentialité de sa cartographie | [`crypto.k-node-self`](k-node-self.md) |
| `K_self` | Propre au User, récupération de l'historique d'attachement | [`crypto.k-self`](k-self.md) |
| `K_emergency_content` / `sig_priv_emergency` | Dérivées de `K_attach`, espace de secours | [`protocols.espace-secours`](../04-protocols/espace-secours.md) |

Clés de signature dédiées (`sig_priv_user`, `sig_priv_dispersal`,
`priv_node_recovery`) : voir
[`network.dht-directory`](../01-network-dht/dht-directory.md) et
[`securite.incidents-compromissions`](../05-securite/incidents-compromissions.md).

Continuité à travers les rotations : voir
[`crypto.master-key-chain`](master-key-chain.md).

Migration post-quantique de cette hiérarchie : voir
[`agilite.kem-vs-nike`](../08-agilite-crypto/kem-vs-nike.md).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
