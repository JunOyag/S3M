---
id: node.AttachedUser
kind: schema
title: "AttachedUser"
section: "§3.11"
fbs_source: "schemas/node/NodeManifest.fbs#AttachedUser"
status: draft
verified_by: []
---

# AttachedUser

Un utilisateur rattaché à ce Nœud.

## Champs

```
--8<-- "node/AttachedUser.table.md"
```

## `user_id` n'est pas un identifiant opaque

`user_id` n'est autre que `pub_user` (clé publique Ed25519 brute) — pas un
identifiant séparé. Combiné à `salt` (fixé par le Connecteur à
l'attachement), le Nœud dispose directement des deux seules données
externes nécessaires pour re-dériver
[`crypto.k-attach`](../../03-crypto/k-attach.md) à tout moment, **sans
consultation de la DHT**.

## Agilité cryptographique

`key_algorithm` et `kem_ciphertext` sont des champs additifs (§3.5)
préparant la bascule post-quantique — voir
[`agilite.k-attach-kem`](../../08-agilite-crypto/k-attach-kem.md) et
[`agilite.tag-hybride`](../../08-agilite-crypto/tag-hybride.md). En mode
Ed25519/X25519 (`key_algorithm = 0`, valeur par défaut de ce document),
`kem_ciphertext` reste vide.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
