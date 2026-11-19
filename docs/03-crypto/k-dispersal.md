---
id: crypto.k-dispersal
kind: narrative
title: "K_dispersal_content / K_dispersal_block"
section: "§3.8"
status: draft
verified_by: []
---

# K_dispersal_content / K_dispersal_block — Blocs Internes de l'Arbre d'Index

```
K_dispersal_content = KDF(K_attach, "dispersal-content")
K_dispersal_block   = KDF(K_dispersal_content, "dispersal-block", sel_du_nœud)
```

Instanciation selon la [convention KDF](symmetric-suite.md#kdf-hkdf-sha256).
`sel_du_nœud` est un sel de **16 octets d'un CSPRNG, neuf à chaque émission
d'un `IndexNode`** sérialisé en bloc :

- le sel d'un nœud enfant est porté par la référence que son parent garde
  vers lui ([`dispersal.Stripe`](../02-schemas/dispersal/Stripe.md),
  champ `encryption_salt`) ;
- le sel de la racine de l'arbre est porté par le pointeur publié en DHT
  (`DispersalRootPointer.dispersal_root_salt`, voir
  [`network.dht-directory`](../01-network-dht/dht-directory.md)).

Une clé = un nœud émis = un message : la position du nœud dans l'arbre n'a
pas besoin d'entrer dans la dérivation. `K_dispersal_block` est
**indépendante de `block_hash`** (même raison que
[`crypto.k-block`](k-block.md)) ; le format de bloc chiffré (65 536 o, nonce
aléatoire, AAD = en-tête de version) est celui de
[`crypto.k-block`](k-block.md). Un nœud modifié est réémis en
copy-on-write avec un sel neuf ; les nœuds inchangés gardent leur bloc et
leur sel. Arbitrage du 2026-11-19 (`impl/SPEC_GAPS.md`, point ❓1 de la V3).

Le pointeur `dispersal_root_hash`/`dispersal_root_partners` publié en DHT ne
couvre que la **racine** de l'arbre d'index
([`protocols.index-adaptatif`](../04-protocols/index-adaptatif.md)).
Au-delà de la capacité d'un seul `IndexNode`, les niveaux inférieurs sont
eux-mêmes sérialisés en blocs de 64 KiO, dispersés par erasure coding — ces
blocs ont donc besoin de leur propre chiffrement, sur le principe de
[`crypto.k-block`](k-block.md) mais enraciné dans
[`crypto.k-attach`](k-attach.md) plutôt que dans la clé maîtresse User,
puisque c'est une clé **partagée** Nœud↔Connecteur.

## Séparation délibérée en deux étages

`K_dispersal_content` sert de base à `K_dispersal_block`, mais **ne
permet pas** de reconstituer `K_attach` ni `sig_priv_dispersal = KDF(K_attach,
"dispersal-signing")` — une dérivation à sens unique. Cela permet de
transmettre `K_dispersal_content` à un tiers pour qu'il déchiffre des blocs,
**sans** lui donner la capacité de signer une mise à jour ou une suppression
de l'entrée DHT.

## Conséquence pour la migration

C'est ce qui rend possible le flux décrit dans
[`protocols.migration-noeud`](../04-protocols/migration-noeud.md) : le
Connecteur transmet `dispersal_root_hash`, `dispersal_root_partners`,
`dispersal_root_salt` et
`K_dispersal_content` au nouveau Nœud — jamais `K_attach` ni
`sig_priv_dispersal`. Le nouveau Nœud récupère et déchiffre alors seul les
blocs, en dérivant `K_dispersal_block` nœud par nœud à partir des sels
portés par l'arbre lui-même, **sans intervention
supplémentaire du Connecteur**, tout en restant structurellement incapable
de signer quoi que ce soit sur l'ancienne entrée DHT.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
