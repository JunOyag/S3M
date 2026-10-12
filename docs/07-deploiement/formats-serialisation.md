---
id: deploiement.formats-serialisation
kind: narrative
title: "Formats de Sérialisation et Performance"
section: "§7.2"
status: draft
verified_by: []
---

# Formats de Sérialisation et Performance

- **Format réseau P2P** : en-têtes et protocoles gérés via FlatBuffers (ou
  Cap'n Proto) pour une sérialisation/désérialisation à coût zéro
  (zero-copy) et un très faible usage CPU/RAM. Voir les schémas sources
  sous `schemas/**/*.fbs`, dont dérivent toutes les pages
  [`02-schemas`](../02-schemas/dispersal/DispersalManifest.md).
- **Stockage local** : base SQLite en mode WAL ou LMDB pour les accès
  clé-valeur instantanés — voir
  [`node.MutationLog`](../02-schemas/node/MutationLog.md) pour le détail du
  cycle append-only → compaction.
- **Payload** : octets bruts chiffrés avec en-tête fixe de 2 octets pour la
  version.
- **En-tête de version (2 o)** : `u16` **gros-boutiste** (convention réseau,
  comme l'encodage canonique de [`crypto.symmetric-suite`](../03-crypto/symmetric-suite.md)) ;
  `0x0000` réservé et interdit ; **valeur courante `1`** pour ce cycle de
  développement. L'incrémentation (versions suivantes) est décidée par
  orchestration d'évolutions disruptives : les implémentations des différentes
  versions **coexistent**, aucun bump silencieux. Portée : préfixe des trames
  chiffrées et donnée authentifiée (AAD) — y compris pour le wrap, où l'en-tête
  n'existe **qu'en AAD** (`wrapped_key` = 48 o sans en-tête, voir la clé de wrap
  de [`crypto.symmetric-suite`](../03-crypto/symmetric-suite.md) et la lecture
  d'un bloc ancien de [`crypto.master-key-chain`](../03-crypto/master-key-chain.md)).
  Un bump de version change l'AAD : tous les chiffrés déterministes (blocs à
  nonce synthétique) changent avec lui — corollaire assumé, même logique que la
  rotation de clé.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
