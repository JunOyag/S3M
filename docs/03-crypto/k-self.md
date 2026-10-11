---
id: crypto.k-self
kind: narrative
title: "K_self — Récupération depuis la Seed"
section: "§3.8"
status: draft
verified_by: []
---

# K_self — Récupération de l'Historique d'Attachement depuis la Seed

```
K_self = KDF(priv_user, "attachment-recovery")
```

Dérivée uniquement de la clé privée du User — ne dépend d'aucune information
externe. `priv_user` elle-même dérive de la phrase mnémonique BIP-39 selon
un schéma de chemins fixe — voir
[crypto.identity-derivation](identity-derivation.md).

## Rôle

Auto-chiffre, dans l'entrée DHT publique du User (voir
[`network.dht-directory`](../01-network-dht/dht-directory.md)), la **liste
complète des tuples d'attachement** `{node_id, salt, timestamp,
inactivity_detected_at}` — l'attachement courant et tous les précédents.
Seul le User (via sa seed BIP-39) peut déchiffrer cette liste.

## Reconstruction complète depuis la seed seule

Permet une reconstruction complète même en cas de perte totale de
l'appareil du Connecteur :

1. Identité User → entrée DHT.
2. Déchiffrement de la liste `{node_id, salt, timestamp,
   inactivity_detected_at}` avec `K_self`.
3. Dérivation de [`crypto.k-attach`](k-attach.md) pour l'attachement voulu
   (courant ou passé).
4. Localisation et lecture du
   [`dispersal.DispersalManifest`](../02-schemas/dispersal/DispersalManifest.md)
   correspondant.

Ce flux est la même logique que celle détaillée pour le Nœud dans
[`deploiement.disaster-recovery`](../07-deploiement/disaster-recovery.md),
côté User.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
