---
id: crypto.k-node-self
kind: narrative
title: "K_node_self — Confidentialité de la Cartographie Nœud"
section: "§3.8"
status: draft
verified_by: []
---

# K_node_self — Confidentialité de la Cartographie de Dispersion du Nœud

```
K_node_self = KDF(priv_node, "node-recovery")
```

Dérivée uniquement de la clé privée du Nœud — symétrique de
[`crypto.k-self`](k-self.md) côté User. `priv_node` elle-même dérive de la
phrase mnémonique BIP-39 selon un schéma de chemins fixe — voir
[`crypto.identity-derivation`](identity-derivation.md).

## Ce qu'elle protège

Chiffre `node_snapshot_root_hash` et `node_snapshot_root_partners` dans
l'entrée DHT publique du Nœud (voir
[`network.dht-directory`](../01-network-dht/dht-directory.md)). Sans ce
chiffrement, un observateur externe pourrait scanner la DHT et reconstruire
le graphe des relations de dispersion entre nœuds à partir des partenaires
en clair.

Seul le Nœud (via sa propre seed) peut déchiffrer — y compris après une
restauration complète
([`deploiement.disaster-recovery`](../07-deploiement/disaster-recovery.md)),
puisque la clé est dérivable depuis la seed seule, sans dépendre d'un état
local préservé.

## Liste noire — même protection au repos

La liste noire ([`node.BlacklistedPartner`](../02-schemas/node/BlacklistedPartner.md),
champ de [`node.NodeManifest`](../02-schemas/node/NodeManifest.md))
bénéficie de la même protection au repos (chiffrement par la clé maîtresse
locale du Nœud) et reste donc elle aussi invisible à tout observateur
externe — cohérent avec le choix de ne jamais la diffuser sur le réseau
(voir [`securite.blacklist-fraude`](../05-securite/blacklist-fraude.md)).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
