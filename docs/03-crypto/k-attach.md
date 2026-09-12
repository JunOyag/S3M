---
id: crypto.k-attach
kind: narrative
title: "K_attach — Métadonnées de Dispersion"
section: "§3.8"
status: draft
verified_by: []
---

# K_attach — Métadonnées de Dispersion

Clé partagée **Nœud ↔ Connecteur**, propre à un attachement (User, Node)
donné. Chiffre exclusivement le contenu du
[`dispersal.DispersalManifest`](../02-schemas/dispersal/DispersalManifest.md)
— jamais le contenu réel des blocs (ça, c'est le rôle de
[`crypto.k-block`](k-block.md)).

## Dérivation

Les identités (`priv_user`/`pub_user`, `priv_node`/`pub_node`) sont des paires
Ed25519. Pour éviter de mélanger primitives de signature et d'échange de
clé, chaque partie convertit sa paire en X25519 avant l'échange :

```
priv_user_x25519 = ed25519_to_x25519(priv_user)
pub_node_x25519  = ed25519_to_x25519(pub_node)
K_attach = KDF(X25519(priv_user_x25519, pub_node_x25519), salt)
```

Côté Nœud, calcul symétrique avec ses propres clés. Le `salt` est fixé par
le **Connecteur** au moment de l'attachement — stocké côté Nœud dans
[`node.AttachedUser`](../02-schemas/node/AttachedUser.md), côté Connecteur
dans l'historique `attachments` de l'entrée DHT User (voir
[`network.dht-directory`](../01-network-dht/dht-directory.md)).

!!! note "Pourquoi convertir Ed25519 → X25519 plutôt qu'utiliser directement une paire X25519 ?"
    Réutiliser une même paire de clés pour signature (Ed25519) et échange
    (X25519 brut) est un mélange de primitives à proscrire. La conversion
    birationnelle standard permet de dériver les deux usages depuis une
    **seule** seed BIP-39, sans clé supplémentaire à gérer — cohérent avec
    [`deploiement.disaster-recovery`](../07-deploiement/disaster-recovery.md).

## Reconstruction côté Nœud — sans consultation DHT

`pub_user` est stocké directement comme `user_id` dans
[`node.AttachedUser`](../02-schemas/node/AttachedUser.md) (pas un identifiant
opaque séparé), et `salt` y est également conservé. Le Nœud dispose donc
localement des deux seules données externes nécessaires : aucune requête DHT
n'est requise pour re-dériver `K_attach` à tout moment.

## Portée de signature dérivée

```
sig_priv_dispersal = KDF(K_attach, "dispersal-signing")
```

Les deux parties peuvent calculer cette paire, mais **seul le Nœud signe**
en fonctionnement normal — voir
[`protocols.dispersion-transactionnelle`](../04-protocols/dispersion-transactionnelle.md)
et [`protocols.suppression-dispersal`](../04-protocols/suppression-dispersal.md)
pour la justification de cette asymétrie et ses implications en migration.

## Clés dérivées de K_attach

`K_attach` sert elle-même de racine à d'autres clés à portée plus étroite —
détaillées sur leur propre page plutôt que redites ici :

- [`crypto.k-dispersal`](k-dispersal.md) — chiffrement des blocs internes de
  l'arbre d'index (`K_dispersal_content` / `K_dispersal_block`)
- espace de secours (`K_emergency_content`, `sig_priv_emergency`) — voir
  [`protocols.espace-secours`](../04-protocols/espace-secours.md)

## Migration post-quantique

Le redesign de `K_attach` en mode KEM (ML-KEM) casse une propriété implicite
de cette page (re-dérivation gratuite côté Connecteur) — traité séparément
dans [`agilite.k-attach-kem`](../08-agilite-crypto/k-attach-kem.md) pour ne
pas alourdir la description du schéma de référence ci-dessus.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
