---
id: node.MutationLog
kind: schema
title: "MutationLog"
section: "§3.5, §3.11"
fbs_source: "schemas/node/MutationLog.fbs#MutationLog"
status: draft
verified_by: []
---

# MutationLog

Journal complet des [`node.Mutation`](Mutation.md), rejoué au démarrage.

## Champs

```
--8<-- "node/MutationLog.table.md"
```

## Cycle append-only → compaction

Les mutations sont d'abord append-only dans une table dédiée d'une base
SQLite (mode WAL) ou LMDB, puis rejouées/compactées périodiquement en un
fichier FlatBuffers complet — déclencheur : le premier seuil atteint entre
une taille de journal (~1 MiO) et un intervalle fixe (horaire).

**Démarrage** : rejeu du journal non compacté → reconstruction du cache
d'index → chargement du dernier fichier FlatBuffers compacté comme état de
référence. Ce même mécanisme sert de base à la restauration complète du
Nœud, voir
[`deploiement.disaster-recovery`](../../07-deploiement/disaster-recovery.md).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
