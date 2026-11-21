---
id: deploiement.disaster-recovery
kind: narrative
title: "Gestion des Clés (Disaster Recovery)"
section: "§7.1"
status: draft
verified_by: []
---

# Gestion des Clés (Disaster Recovery)

Dérivation cryptographique basée sur BIP-39 (phrases mnémoniques — schéma
de chemins :
[`crypto.identity-derivation`](../03-crypto/identity-derivation.md)). C'est de
ces seeds que dérivent toutes les clés opérationnelles
([`crypto.key-hierarchy`](../03-crypto/key-hierarchy.md)) ainsi que les clés
de signature et l'espace de secours.

## Snapshot du NodeManifest {: #snapshot }

Précisions d'implémentation (2026-11-20, `impl/SPEC_GAPS.md`) :

- **Contenu** : [`node.NodeManifest`](../02-schemas/node/NodeManifest.md)
  — Utilisateurs rattachés (sel, quota), comptes partenaires (fragments
  confiés et reçus ; `allowance_blocks`, ignoré, vaut 0), liste noire. Les conteneurs
  physiques n'y figurent pas : la restauration réécrit les blocs.
- **Chiffrement** : `K_node_snapshot = KDF(priv_node, "node-snapshot",
  sel, u32(i))`, sel de 16 o neuf à chaque émission, format de bloc de
  [`crypto.k-block`](../03-crypto/k-block.md). Le clair `u32be(longueur) ‖
  NodeManifest` est réparti sur les k blocs de données d'un stripe
  (k × 65 506 o au plus).
- **Dispersion** : un stripe complet, comme les stripes d'index
  ([`protocols.dispersion-transactionnelle`](../04-protocols/dispersion-transactionnelle.md#orchestration)),
  réémis dès que le contenu change ; l'ancien est purgé par tombstones.
- **Pointeur** : `NodeSnapshotPointer` de l'entrée DHT Node, avec les champs
  additifs `node_snapshot_root_salt` et `node_snapshot_root_stripe`
  (hashes des fragments, demandés par hash). `node_snapshot_root_hash` est
  le hash du bloc 0.
- **Restauration** : nouvelle installation avec la seule seed (base locale
  vide, au moins un Nœud d'amorçage DHT) : lecture de sa propre entrée
  Node, reconstruction du snapshot depuis k fragments, puis, pour chaque
  Utilisateur rattaché, lecture de son `DispersalManifest` et
  reconstruction des blocs de données depuis la parité (étape 4).

## Procédure de restauration

1. Réinitialisation d'un nœud à partir de la seed « Node ».
2. Résolution du `node_snapshot_root_hash` du manifeste sur la DHT
   (déchiffrement via [`crypto.k-node-self`](../03-crypto/k-node-self.md)).
3. Récupération de k fragments sur N et restauration de la base
   SQLite/LMDB locale (liste noire incluse, voir
   [`node.BlacklistedPartner`](../02-schemas/node/BlacklistedPartner.md), et
   comptes partenaires, [`node.PartnerAccount`](../02-schemas/node/PartnerAccount.md)) —
   cela inclut l'état des fichiers de conteneur physiques
   ([`node.ContainerFile`](../02-schemas/node/ContainerFile.md), bitmaps
   compris), voir
   [`protocols.stockage-physique`](../04-protocols/stockage-physique.md#restauration-disaster-recovery)
   pour le détail de cette restauration et le repli par scan si le cache
   fin ([`node.BlockLocation`](../02-schemas/node/BlockLocation.md)) n'a
   pas survécu intact.
4. Pour chaque [`node.AttachedUser`](../02-schemas/node/AttachedUser.md), le
   Nœud recalcule `K_attach` (symétrique) et accède au
   [`dispersal.DispersalManifest`](../02-schemas/dispersal/DispersalManifest.md)
   correspondant. Il reconstruit en local les k blocs de données, stripe
   par stripe, à partir des blocs de parité — retrouvant sa « copie locale
   intégrale » sans qu'aucun bloc de données n'ait eu besoin d'être
   sauvegardé ailleurs que sous forme de parité.
5. Authentification du Connecteur via la seed « Utilisateur ».
6. Récupération de `fs_root_hash` (déchiffrement via
   [`crypto.k-self`](../03-crypto/k-self.md)) et reconstruction des
   fichiers — pour les blocs antérieurs à une rotation de clé passée, la
   [`crypto.master-key-chain`](../03-crypto/master-key-chain.md) récupérée
   permet de dériver la `master_key[version]` historique, sans opération
   réseau supplémentaire.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
