---
id: crypto.k-block
kind: narrative
title: "K_block — Contenu Réel des Blocs"
section: "§3.8"
status: draft
verified_by: []
---

# K_block — Contenu Réel des Blocs

```
K_block = KDF(master_key[version], block_hash, encryption_salt)
```

- Dérivée uniquement de la seed BIP-39 du User — **jamais partagée avec le
  Nœud**.
- Une clé distincte par bloc (`block_hash` + `encryption_salt`), révocable
  individuellement sans affecter les autres blocs.
- `encryption_salt` est fixé une fois par fichier (ou par répertoire), porté
  par l'entrée FS correspondante
  ([`fs.DirectoryEntry`](../02-schemas/fs/DirectoryEntry.md)) — tous les
  blocs d'un même fichier/répertoire le partagent, seul `block_hash` varie.

## Chiffrement avant envoi, jamais côté Nœud

Le Connecteur chiffre les blocs avec `K_block` **avant même l'envoi au
Nœud**. Le Nœud calcule les blocs de parité Reed-Solomon directement sur le
texte chiffré (opération linéaire, valide sans déchiffrement — voir
[`protocols.erasure-coding`](../04-protocols/erasure-coding.md)) et **ne
détient ni ne dérive jamais `K_block`**.

Conséquence directe : la « copie locale intégrale » que conserve le Nœud
(ratio 4x, voir [`overview.architecture`](../00-overview/architecture.md))
est constituée de blocs déjà chiffrés — le Nœud calcule le hash de challenge
PoS ([`securite.pos-challenges`](../05-securite/pos-challenges.md)) et les
fragments de parité sur ce texte chiffré, sans jamais avoir besoin ni la
capacité de déchiffrer.

## Versionnement

`master_key[version]` n'est pas figée à vie — voir
[`crypto.master-key-chain`](master-key-chain.md) pour le mécanisme complet
de continuité à travers les rotations, et la justification des deux
emplacements de `key_version`.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
