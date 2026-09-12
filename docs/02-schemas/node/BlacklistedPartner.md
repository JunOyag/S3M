---
id: node.BlacklistedPartner
kind: schema
title: "BlacklistedPartner"
section: "§3.11, §5.3.5"
fbs_source: "schemas/node/NodeManifest.fbs#BlacklistedPartner"
status: draft
verified_by: []
---

# BlacklistedPartner

Un partenaire exclu suite à une fraude PoS avérée.

## Champs

```
--8<-- "node/BlacklistedPartner.table.md"
```

Champ additif du schéma [`node.NodeManifest`](NodeManifest.md), ajouté
conformément à la règle d'évolution additive-only. Persistée en local, **sans
partage ni diffusion réseau** — la décision reste strictement privée à
l'instance qui a détecté la fraude. Mécanisme de détection, de rupture et
limites (régénération d'identité après le délai VDF minimal) détaillés dans
[`securite.blacklist-fraude`](../../05-securite/blacklist-fraude.md).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
