---
id: node.NodeManifest
kind: schema
title: "NodeManifest"
section: "§3.3, §3.11"
fbs_source: "schemas/node/NodeManifest.fbs#NodeManifest"
status: draft
verified_by: []
---

# NodeManifest

Racine du manifeste Nœud — structure d'indexation locale gérée
exclusivement par le nœud, chiffrée au repos avec
[`crypto.k-node-self`](../../03-crypto/k-node-self.md).

## Champs

```
--8<-- "node/NodeManifest.table.md"
```

Le Connecteur n'a **jamais** accès à cette structure — symétriquement, le
Nœud n'a jamais accès au contenu déchiffré du `UserManifest` ni au contenu
réel des blocs utilisateur.

Le catalogue détaillé des stripes/blocs/partenaires distants n'est **pas**
stocké ici mais dans un
[`dispersal.DispersalManifest`](../dispersal/DispersalManifest.md) séparé,
par couple (Utilisateur, Nœud).

## Stockage physique (ajout post-V2)

Depuis l'ajout de [`node.ContainerFile`](ContainerFile.md), `NodeManifest`
porte aussi un champ `containers` : la liste des fichiers de conteneur de
4 GiO sur lesquels sont physiquement disposés les blocs de ce Nœud (données
locales, parité hébergée en réciprocité, dépôts de secours). Voir
[`protocols.stockage-physique`](../../04-protocols/stockage-physique.md)
pour le mécanisme complet — absent de la spécification d'origine.

## Cycle de vie

Sérialisé en FlatBuffers, réécrit à chaque mutation ; le journal append-only
associé est [`node.MutationLog`](MutationLog.md). Restauré depuis la seed
BIP-39 du Nœud — voir
[`deploiement.disaster-recovery`](../../07-deploiement/disaster-recovery.md).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
