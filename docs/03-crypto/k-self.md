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

Instanciation selon la [convention KDF](symmetric-suite.md#kdf-hkdf-sha256) : IKM = `priv_user`, sans sel ni entrée
publique.

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

## K_root — descripteur scellé de la racine {: #k-root }

Ajout du 2026-11-25. L'entrée User expire après 6 mois sans appareil
connecté ([`network.dht-directory`](../01-network-dht/dht-directory.md)) ;
or le `encryption_salt` de la racine
([`crypto.k-block`](k-block.md), tiré à chaque nouvelle racine) n'est pas
déductible de la seed. Le Connecteur confie donc aussi à son Nœud, à chaque
validation de racine, un **descripteur scellé** :

```
K_root = KDF(priv_user, "root-descriptor")
root_seal = 0x01 ‖ nonce (12) ‖ AEAD(K_root, nonce, aad = fs_root_hash,
                                     encryption_salt (16) ‖ key_version (2, BE))
```

47 octets, clé dédiée (un usage par clé, §3.8) dérivée de la seed seule.
Le Nœud le garde avec la racine sans pouvoir l'ouvrir, et le renvoie avec
elle ([`protocols.echange-blocs`](../04-protocols/echange-blocs.md#descripteur-de-racine)).
L'AAD lie le descripteur à sa racine : détaché d'elle, il ne s'ouvre pas.
Un Nœud malveillant ne peut que servir une ancienne racine complète avec son
descripteur — risque déjà assumé pour la racine seule (§3.12). Tant que le
Nœud garde les données, la seed suffit donc à les relire, quelle que soit
la durée d'absence ; l'entrée User reste la source quand le Nœud est hors
ligne.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
