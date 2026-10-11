---
id: crypto.master-key-chain
kind: narrative
title: "Continuité de Chiffrement — master_key_chain"
section: "§3.8"
status: draft
verified_by: []
---

# Continuité de Chiffrement — `master_key_chain`

## Problème résolu

[`crypto.k-block`](k-block.md) dérive de la seed BIP-39 du User. Lors d'une
rotation d'identité suite à compromission
([`securite.incidents-compromissions`](../05-securite/incidents-compromissions.md)) —
index d'identité suivant si seule une clé dérivée a fuité, nouvelle phrase
mnémonique si la seed elle-même a fuité (règle :
[`crypto.identity-derivation`](identity-derivation.md)) — la rotation
s'accompagne d'une `master_key` mathématiquement indépendante de l'ancienne
(chemin dédié `m/0x703270'/3'/version'`, voir la section « Clé maîtresse »
de la page citée) :
elle ne permet donc pas, seule, de déchiffrer les blocs existants. Rechiffrer l'intégralité des données dispersées à chaque rotation
serait une opération réseau prohibitive (récupération via le Nœud,
déchiffrement, rechiffrement, redispersion complète).

## Principe : ne conserver que les clés, jamais les données

Seule la **clé maîtresse elle-même** (quelques dizaines d'octets) est
conservée à travers les rotations, sous forme d'une chaîne wrappée :

- Au moment d'une rotation, le Connecteur détient encore brièvement, en
  clair, **toutes** les clés maîtresses historiques. Il les **re-wrappe
  intégralement sous la nouvelle clé maîtresse** — re-wrap *plat*, pas un
  chaînage séquentiel : chaque clé historique reste déchiffrable en une
  seule étape depuis la clé **courante**, quel que soit le nombre de
  rotations passées.
- `master_key_chain: [{version, wrapped_key}]` est republiée dans l'entrée
  DHT du User ([`network.dht-directory`](../01-network-dht/dht-directory.md)),
  chiffrée avec `K_self` courant — même principe et même emplacement que
  l'historique `attachments`.

## Lecture d'un bloc ancien

1. Consulter le `key_version` porté par l'entrée FS correspondante
   ([`fs.DirectoryEntry`](../02-schemas/fs/DirectoryEntry.md) — pas le
   `DispersalManifest`, court-circuité en fonctionnement normal, voir
   [`protocols.acces-applicatif`](../04-protocols/acces-applicatif.md)).
2. Déchiffrer l'entrée `wrapped_key` correspondante dans `master_key_chain`
   avec la clé maîtresse courante → `master_key[version]`.
3. Dériver `K_block = KDF(master_key[version], block_hash, encryption_salt)`.
4. Déchiffrer le bloc.

Coût constant, indépendant du nombre de rotations subies. Les blocs
**nouvellement écrits** après une rotation utilisent systématiquement
`master_key[version_courante]` — aucune donnée existante n'a besoin d'être
touchée.

## Pourquoi deux emplacements pour `key_version` {: #pourquoi-deux-emplacements }

`key_version` est porté à **deux endroits distincts, à dessein** :

- dans [`dispersal.BlockEntry`](../02-schemas/dispersal/BlockEntry.md),
  lisible par le Nœud **et** le Connecteur (chiffré sous `K_attach`) — le
  Nœud en a besoin pour sa comptabilité opérationnelle (réparation, PoS)
  sans jamais avoir accès à la structure FS ;
- dans [`fs.DirectoryEntry`](../02-schemas/fs/DirectoryEntry.md), lisible
  par le **Connecteur uniquement** (sous `K_block`) — le Connecteur s'appuie
  uniquement sur cette entrée en fonctionnement normal, sans jamais
  consulter le `DispersalManifest`.

Ce n'est donc pas une redondance superflue : chaque copie sert une partie
qui n'a structurellement pas accès à l'autre.

## Portée de la fuite en cas de compromission

Un attaquant en possession d'une clé maîtresse compromise pouvait déjà
déchiffrer les blocs de cette version avant la rotation. Conserver cette
même clé (wrappée sous la nouvelle) ne lui donne **aucun accès
supplémentaire** : il ne détient pas la nouvelle clé maîtresse nécessaire
pour déchiffrer le wrap. Seules les données chiffrées **après** la rotation
sont protégées de cet attaquant — la garantie normalement attendue d'une
rotation de clé.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
