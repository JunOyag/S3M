---
id: network.SignedNodeMessage
kind: schema
title: "SignedNodeMessage"
section: "§5.2"
fbs_source: "schemas/network/NodeMessage.fbs#SignedNodeMessage"
status: draft
verified_by: []
---

# SignedNodeMessage

Table source : `schemas/network/NodeMessage.fbs#SignedNodeMessage` (ajout du 2026-11-21).

## Champs

```
--8<-- "network/SignedNodeMessage.table.md"
```

Message sérialisé :

```
--8<-- "network/NodeMessage.table.md"
```

Message d'un Nœud à ses Utilisateurs, signé par `priv_node` (`Info`) ou par
`priv_node_announce` (`Alert`) : libellés et règles de vérification dans
[`protocols.canal-noeud`](../../04-protocols/canal-noeud.md#messages).
Message conservé par le Nœud pour un Utilisateur :

```
--8<-- "network/UserMessage.table.md"
```

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
