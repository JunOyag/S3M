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
K_block = KDF(master_key[version], encryption_salt)
```

- Dérivée uniquement de la seed BIP-39 du User — **jamais partagée avec le
  Nœud**.
- **Indépendante de `block_hash`** : la formule ne lit aucun hash du
  chiffrement qu'elle produit — circularité `block_hash` ↔ `K_block`
  arbitrée dans `impl/SPEC_GAPS.md` (clés sans `block_hash`, chiffrement
  déterministe à nonce synthétique).
- Une clé distincte par **élément** (fichier ou répertoire) : révocable au
  niveau de l'élément sans affecter les autres.
- `encryption_salt` est tiré d'un **CSPRNG à chaque émission**, conservé dans
  la file d'attente locale ([`fs.WriteQueue`](../02-schemas/fs/WriteQueue.md))
  pendant l'attente de synchronisation, puis porté par l'entrée FS
  correspondante
  ([`fs.DirectoryEntry`](../02-schemas/fs/DirectoryEntry.md)) — tous les
  blocs d'un même fichier/répertoire le partagent.

## Chiffrement déterministe, nonce synthétique

`K_block` chiffre des blocs **adressés par contenu** : le chiffrement est
déterministe, avec un **nonce synthétique** (règle de
[`crypto.symmetric-suite`](symmetric-suite.md)) :

```
nonce = 12 premiers octets de HMAC-SHA256(K_nonce, u32(len(AAD)) ‖ AAD ‖ clair)
```

- **AAD d'un bloc** : en-tête de version (2 o) ‖ étiquette de contexte
  `« block »` — aucun champ supplémentaire : deux écritures identiques d'un
  même contenu doivent produire exactement le même chiffré.
- **Trame** : en-tête (2 o) ‖ nonce (12 o) ‖ chiffré ‖ tag (16 o) — surcoût
  de **30 o** ; dans un bloc complet de 64 KiO, **65 506 o de clair**
  (padding zéro du clair jusqu'à 65 506 o).
- `block_hash` est le hash du **chiffré**, calculé après chiffrement — il
  n'entre ni dans `K_block` ni dans le nonce.

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
