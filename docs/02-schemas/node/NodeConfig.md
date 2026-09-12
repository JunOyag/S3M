---
id: node.NodeConfig
kind: schema
title: "NodeConfig"
section: "§3.11"
fbs_source: "schemas/node/NodeManifest.fbs#NodeConfig"
status: draft
verified_by: []
---

# NodeConfig

Configuration opérationnelle du Nœud : volumes, quotas, paramètres de
redondance et de l'espace de secours.

## Champs

```
--8<-- "node/NodeConfig.table.md"
```

## Notes

- `default_replication_coefficient` (coef, 3 par défaut) détermine N = k +
  coef×k blocs par stripe — voir
  [`protocols.erasure-coding`](../../04-protocols/erasure-coding.md).
- `duree_max_idle_seconds` gouverne le padding par timeout d'un paquet
  incomplet, également décrit sur cette même page (assemblage progressif).
- `emergency_reserved_bytes` et `emergency_backup_capacity` dimensionnent la
  capacité de ce Nœud à agir comme **partenaire de secours pour des tiers**
  — détail du calcul (`E_secours = U_backup × (Q_max / n_secours)`) dans
  [`protocols.espace-secours`](../../04-protocols/espace-secours.md).
- `republish_interval` fixe la cadence de republication des entrées DHT
  Node et DispersalManifest — voir
  [`network.dht-directory`](../../01-network-dht/dht-directory.md).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
