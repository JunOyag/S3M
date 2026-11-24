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
  vide ; voir [Restauration automatique](#automatique)) : lecture de sa propre entrée
  Node, reconstruction du snapshot depuis k fragments, puis, pour chaque
  Utilisateur rattaché, lecture de son `DispersalManifest` et
  reconstruction des blocs de données depuis la parité (étape 4).

## Restauration automatique {: #automatique }

Ajout du 2026-11-23. Toute installation vide (ni état ni dispersion)
démarrée avec une seed existante se restaure seule, sans réglage : une
identité tout juste créée (assistant, `s3m-node init`) pose un marqueur à
côté de la seed et saute la restauration. Les étapes, enregistrées sur
disque et reprises après un redémarrage, s'affichent en tête de la vue
d'ensemble du dashboard (faite, en cours, à faire, erreur) :

1. identité et preuve VDF ;
2. Nœuds du réseau joints (réseau local ou Nœuds d'amorçage) ;
3. entrée DHT Node lue ;
4. snapshot reconstruit depuis k fragments ;
5. Utilisateurs, partenaires et liste noire restaurés ;
6. copie locale de chaque Utilisateur reconstruite depuis la parité,
   réessayée à chaque cycle jusqu'au succès ;
7. Utilisateurs repris à leur reconnexion (ci-dessous) ;
8. restauration complète.

**Gel** : tant que les étapes 3 à 5 n'ont pas abouti, le Nœud ne publie
rien (entrée DHT Node, snapshot), ne recherche aucun partenaire et ne
disperse rien — une seed restaurée ne peut plus écraser sa propre
sauvegarde par un snapshot vide. Si, Nœuds joints, aucune entrée Node (ou
une entrée sans snapshot) n'est trouvée pendant 10 minutes, le Nœud est
tenu pour neuf et démarre normalement. Un Utilisateur dont la copie locale
est en cours de reconstruction est tenu hors des cycles de dispersion ; les
blocs qu'il envoie entre-temps restent en attente, puis sont dispersés.

### Reprise à la reconnexion {: #reprise }

Un Utilisateur inconnu du Nœud
dont la demande `Attach`
([`protocols.partenariat-automatique`](../04-protocols/partenariat-automatique.md#rattachement-automatique-des-utilisateurs))
porte un identifiant valide est repris, quelle que soit la politique de
rattachement, si son `DispersalManifest` existe dans la DHT sous
`K_attach(ce Nœud, Utilisateur, sel)` : seul ce Nœud a pu le publier avec ce
sel, c'est la preuve d'un rattachement passé. Le Nœud lui attribue le quota
du rattachement automatique (modifiable), accepte sa prochaine racine telle
quelle (comme pour tout Utilisateur dont il ne connaît encore aucune racine) et reconstruit sa copie locale (étape 6). La reprise vaut aussi pour
une installation existante qui aurait perdu la liste de ses Utilisateurs
(sauvegarde écrasée) ; elle n'est alors jamais gelée.

Un Connecteur ne transmet pas au Nœud une racine dont celui-ci n'a pas le bloc (Nœud recréé sans sauvegarde ni fiche de dispersion retrouvée) : il signale ses fichiers introuvables chez le Nœud et, faute de restauration, conseille de créer une nouvelle identité.

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
