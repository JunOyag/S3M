---
id: network.ContactRecord
kind: schema
title: "ContactRecord"
section: "§3.11"
fbs_source: "schemas/network/UserEntry.fbs#ContactRecord"
status: draft
verified_by: []
---

# ContactRecord

Table source : `schemas/network/UserEntry.fbs#ContactRecord` (ajout du 2026-11-23).

## Champs

```
--8<-- "network/ContactRecord.table.md"
```

Un contact de l'Utilisateur, porté par le champ `contacts` de
[`network.UserEntryPlaintext`](UserEntryPlaintext.md) : il n'existe que
chiffré sous `K_self`, lisible par l'Utilisateur sur ses seuls appareils.
`user_id` est unique dans la liste ; `pseudo` suit les règles de
[`deploiement.pseudos`](../../07-deploiement/pseudos.md#regles) et ne
prouve rien. `updated_at` et `deleted` servent à la fusion entre appareils :
[`deploiement.contacts`](../../07-deploiement/contacts.md#fusion).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
