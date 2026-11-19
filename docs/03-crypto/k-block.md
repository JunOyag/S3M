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
K_block = KDF(master_key[version], "block", encryption_salt, u32(index_du_bloc))
```

Instanciation selon la [convention KDF](symmetric-suite.md#kdf-hkdf-sha256) :
IKM = `master_key[version]`, étiquette `"block"`, sel = `encryption_salt`,
entrée publique = index du bloc en `u32` big-endian.

- Dérivée uniquement de la seed BIP-39 du User — **jamais partagée avec le
  Nœud**.
- **`K_block` ne dépend pas du `block_hash`.** Le `block_hash` est le hash
  du texte chiffré ; en dépendre créerait une circularité (il faudrait
  connaître le hash d'un bloc pour le chiffrer). La clé dépend de la
  **position** du bloc dans sa chaîne (`index_du_bloc`, 0 pour le premier
  bloc de la chaîne) et du `encryption_salt` de la version du fichier ou du
  répertoire.
- **`encryption_salt` est neuf (16 octets d'un CSPRNG) à chaque création ou
  réémission** d'un fichier ou d'un répertoire. Il est conservé dans la file
  d'attente locale ([`fs.WriteQueue`](../02-schemas/fs/WriteQueue.md))
  pendant l'attente de synchronisation, puis porté par l'entrée FS
  correspondante ([`fs.DirectoryEntry`](../02-schemas/fs/DirectoryEntry.md)) ;
  celui du répertoire racine est porté par l'entrée DHT User. **Règle
  impérative : un `encryption_salt` n'est jamais réutilisé pour un contenu
  différent.** Une écriture interrompue puis reprise repart avec un sel neuf.
- **Granularité de révocation** : une clé distincte par version d'élément
  (sel) et par position — révoquer une version revient à supprimer ses
  blocs ([`protocols.tombstones`](../04-protocols/tombstones.md)).

## Format d'un bloc chiffré

Chaque bloc de données stocké fait exactement **65 536 octets** :

```
version (2 o) ‖ nonce (12 o, aléatoire) ‖ chiffré ‖ tag (16 o)
```

- AEAD **ChaCha20-Poly1305** sous `K_block`
  ([`crypto.symmetric-suite`](symmetric-suite.md)). Chaque `K_block` ne
  chiffre qu'**un** bloc ; le nonce aléatoire est une défense en profondeur.
- **AAD** : l'en-tête de version de 2 octets.
- Clair utile : `65 536 − 2 − 12 − 16 = 65 506` octets. Le `FileBlock` ou le
  `DirectoryBlock` sérialisé (FlatBuffers) est complété par du padding à
  zéro à droite jusqu'à cette taille.
- La capacité utile d'un `FileBlock` (`FILE_BLOCK_DATA_BYTES`) est mesurée
  par un test : plus grande taille de `data` pour laquelle le `FileBlock`
  sérialisé (avec `next_hash` et surcoût FlatBuffers) tient dans 65 506 o —
  de l'ordre de 65 400 o.
- `block_hash` est le hash SHA-256 du bloc chiffré complet de 65 536 o,
  calculé après chiffrement. Une chaîne se chiffre donc **du dernier bloc
  vers le premier** : chaque bloc porte le `next_hash` du suivant
  ([`protocols.fs-structure`](../04-protocols/fs-structure.md)).

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
