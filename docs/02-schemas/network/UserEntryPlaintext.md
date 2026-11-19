---
id: network.UserEntryPlaintext
kind: schema
title: "UserEntryPlaintext"
section: "§3.9, §3.11"
fbs_source: "schemas/network/UserEntry.fbs#UserEntryPlaintext"
status: draft
verified_by: []
---

# UserEntryPlaintext

Table source : `schemas/network/UserEntry.fbs#UserEntryPlaintext` (V3).

## Champs

```
--8<-- "network/UserEntryPlaintext.table.md"
```

Clair chiffré sous [`crypto.k-self`](../../03-crypto/k-self.md) dans le
champ `ciphertext` de [`network.UserEntry`](UserEntry.md). Porte la racine
du système de fichiers (`fs_root_hash` et le sel `encryption_salt` du
répertoire racine, neuf à chaque réémission), l'historique des
attachements et la [`crypto.master-key-chain`](../../03-crypto/master-key-chain.md).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
