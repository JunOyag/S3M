---
id: dispersal.BlockEntry
kind: schema
title: "BlockEntry"
section: "§3.11"
fbs_source: "schemas/dispersal/DispersalManifest.fbs#BlockEntry"
status: draft
verified_by: []
---

# BlockEntry

Une entrée de bloc — donnée **ou** parité — au sein d'une
[`dispersal.Stripe`](Stripe.md).

## Champs

Les champs ci-dessous sont **générés depuis `schemas/dispersal/DispersalManifest.fbs`**
par `scripts/fbs_to_jsonschema.py` — ne jamais les retaper ici, éditer le `.fbs`
puis relancer le build.

```
--8<-- "dispersal/BlockEntry.table.md"
```

Schéma JSON complet (avec `$ref` résolus) : `build/schemas/dispersal/BlockEntry.schema.json`.

## Invariant structurel : `block_index` détermine la nature de `partner_id`

C'est la règle la plus facilement mal comprise de ce schéma, donc explicitée
ici plutôt que dans un commentaire de champ isolé :

| `block_index` | Nature du bloc | `partner_id` |
|---|---|---|
| `0` à `k-1` | Donnée originale | **Sentinelle obligatoire** — ce bloc n'est jamais dispersé, il reste exclusivement sur le nœud hébergeur |
| `k` à `N-1` | Parité Reed-Solomon | Référence réelle vers une entrée de [`dispersal.Partner`](Partner.md) |

Cette distinction découle directement du principe d'empreinte disque décrit
dans [`overview.architecture`](../../00-overview/architecture.md) (ratio 4x :
1 copie locale + 3x parité) — elle n'est pas répétée ici, seulement
référencée.

## `key_version` — pourquoi ce champ existe aussi ailleurs

`key_version` est porté **à deux endroits distincts, à dessein** : ici (lisible
par le Nœud et le Connecteur, sous `K_attach`) et dans
[`fs.DirectoryEntry`](../fs/DirectoryEntry.md) (lisible par le Connecteur
seul, sous `K_block`). Le détail de ce choix — et pourquoi ce n'est **pas**
une duplication superflue mais une séparation de portée délibérée — est
traité dans [`crypto.master-key-chain`](../../03-crypto/master-key-chain.md#pourquoi-deux-emplacements),
qui reste l'unique endroit où cette justification est rédigée.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
