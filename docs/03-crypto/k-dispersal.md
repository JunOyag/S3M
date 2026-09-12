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
K_dispersal_block   = KDF(K_dispersal_content, block_hash)
```

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

`K_dispersal_content` sert de base à tous les `K_dispersal_block`, mais **ne
permet pas** de reconstituer `K_attach` ni `sig_priv_dispersal = KDF(K_attach,
"dispersal-signing")` — une dérivation à sens unique. Cela permet de
transmettre `K_dispersal_content` à un tiers pour qu'il déchiffre des blocs,
**sans** lui donner la capacité de signer une mise à jour ou une suppression
de l'entrée DHT.

## Conséquence pour la migration

C'est ce qui rend possible le flux décrit dans
[`protocols.migration-noeud`](../04-protocols/migration-noeud.md) : le
Connecteur transmet `dispersal_root_hash`, `dispersal_root_partners` et
`K_dispersal_content` au nouveau Nœud — jamais `K_attach` ni
`sig_priv_dispersal`. Le nouveau Nœud récupère et déchiffre alors seul les
blocs, en dérivant `K_dispersal_block` bloc par bloc, **sans intervention
supplémentaire du Connecteur**, tout en restant structurellement incapable
de signer quoi que ce soit sur l'ancienne entrée DHT.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
