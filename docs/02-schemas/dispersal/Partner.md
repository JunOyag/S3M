---
id: dispersal.Partner
kind: schema
title: "Partner"
section: "§3.11"
fbs_source: "schemas/dispersal/DispersalManifest.fbs#Partner"
status: draft
verified_by: []
---

# Partner

Table de correspondance `partner_id → node_id/ip/port`, **dédupliquée** :
stockée une seule fois par [`dispersal.DispersalManifest`](DispersalManifest.md),
référencée depuis chaque [`dispersal.BlockEntry`](BlockEntry.md) par un simple
`uint16` plutôt que de répéter l'identité complète du partenaire à chaque
entrée de bloc — c'est le mécanisme anti-duplication déjà présent *dans le
protocole lui-même* (§3.4), que cette documentation reproduit à son propre
niveau (schéma ↔ doc) par le même principe de référence plutôt que copie.

## Champs

```
--8<-- "dispersal/Partner.table.md"
```

## Notes

- `partner_id` n'est unique **qu'à l'intérieur** d'un `DispersalManifest`
  donné (pas un identifiant global) — voir
  [`dispersal.DispersalManifest`](DispersalManifest.md) pour la portée.
- La sélection des partenaires eux-mêmes (distance XOR) est un sujet
  protocolaire distinct de ce schéma : voir
  [`protocols.dispersion-transactionnelle`](../../04-protocols/dispersion-transactionnelle.md).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
