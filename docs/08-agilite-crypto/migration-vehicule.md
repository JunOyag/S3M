---
id: agilite.migration-vehicule
kind: narrative
title: "Véhicule de Migration (Réutilisation)"
section: "§8.5"
status: draft
verified_by: []
---

# Véhicule de Migration

Une bascule d'algorithme ne nécessite **aucun nouveau mécanisme** : elle
réutilise tel quel :

- la **clé de secours et le `migration_pointer`** déjà spécifiés pour le
  Nœud — voir
  [`securite.incidents-compromissions`](../05-securite/incidents-compromissions.md) ;
- le **`master_key_chain`** déjà spécifié pour le User — voir
  [`crypto.master-key-chain`](../03-crypto/master-key-chain.md).

Une migration d'algorithme est traitée comme une migration d'identité
volontaire et planifiée, avec la même procédure que pour une compromission
ou une perte, la seule différence étant que le déclencheur est un choix de
bascule de version de protocole plutôt qu'un incident.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
