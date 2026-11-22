---
id: network.dht-directory
kind: narrative
title: "Annuaire DHT & Entrées Publiées"
section: "§2.1, §3.9"
status: draft
verified_by: []
---

# Annuaire DHT & Entrées Publiées

La DHT Kademlia agit uniquement comme un annuaire public indexé par
l'Identité unique. Elle ne stocke **aucun identifiant de bloc individuel**
ni la cartographie des stripes. Elle n'offre **aucune opération de
suppression** pour l'`EmergencyManifest` : une entrée cesse d'être valide à
l'expiration de sa durée de vie.

## Clés de recherche

- **Node** : `pub_node` (octets bruts) — découverte publique nécessaire à
  l'appairage.
- **User** : `user_dht_key = KDF(priv_user, "dht-lookup", —, pub_user)`
  ([convention KDF](../03-crypto/symmetric-suite.md#kdf-hkdf-sha256)) —
  jamais la clé publique brute. Connaître `pub_user` ne suffit donc pas à
  localiser l'entrée ; seul le User (via sa clé privée) peut la calculer.
- **DispersalManifest** : `dht_key = SHA-256(K_attach)` — voir
  [`crypto.k-attach`](../03-crypto/k-attach.md).
- **EmergencyManifest** : `emergency_dht_key = SHA-256(K_attach ‖ "emergency")`
  — voir [`protocols.espace-secours`](../04-protocols/espace-secours.md).
- **Alert** : `SHA-256(pub_node_announce ‖ "alert")` — voir
  [`protocols.canal-noeud`](../04-protocols/canal-noeud.md#annuaire).
- **Share** : `SHA-256(sig_pub_share ‖ "share")` — voir
  [`protocols.partage`](../04-protocols/partage.md#pointeur). Comme pour
  Alert, un pair n'accepte l'enveloppe que si sa clé de signature
  correspond à la clé de recherche.

## Enveloppe signée

**Toute entrée DHT est transportée dans une
[`network.DhtEnvelope`](../02-schemas/network/DhtEnvelope.md)**
`{key_algorithm, payload, signature}` :

- `payload` est la sérialisation FlatBuffers de l'entrée
  ([`network.NodeEntry`](../02-schemas/network/NodeEntry.md),
  [`network.UserEntry`](../02-schemas/network/UserEntry.md),
  [`network.DispersalEntry`](../02-schemas/network/DispersalEntry.md) ou
  [`network.EmergencyEntry`](../02-schemas/network/EmergencyEntry.md)).
  Chaque type porte son propre `file_identifier` FlatBuffers (`"NODE"`,
  `"USER"`, `"DISP"`, `"EMRG"`, `"ALRT"`), vérifié avant tout décodage : un payload
  n'est jamais décodé sous un mauvais type.
- `signature` est une signature **Ed25519** sur
  `L(libellé de signature du type) ‖ payload`, où `payload` désigne les
  **octets exacts tels que transmis**. Le vérificateur contrôle ces octets
  reçus et ne réserialise jamais ; le champ de signature n'est pas dans le
  buffer signé. `L(·)` est l'encodage de longueur de la
  [convention KDF](../03-crypto/symmetric-suite.md#kdf-hkdf-sha256)
  (4 octets big-endian).

### Clés de vérification et libellés de signature

La séparation de contexte est **uniforme** (arbitrage du 2026-11-19, point
❓3 de la V3) : aucune signature d'une clé ne peut être confondue avec une
signature d'un autre type par la même clé.

| Signé | Clé de vérification | Libellé de signature |
|---|---|---|
| `NodeEntry` | `pub_node` (clé de recherche) | `"s3m/sig/node-entry/v1"` |
| `UserEntry` | `sig_pub_user` (publiée en clair dans le payload) | `"s3m/sig/user-entry/v1"` |
| `DispersalEntry` | `sig_pub_dispersal` (en clair dans le payload) | `"s3m/sig/dispersal-entry/v1"` |
| `EmergencyEntry` | `sig_pub_emergency` (en clair dans le payload) | `"s3m/sig/emergency-entry/v1"` |
| `MigrationPointerPayload` | `pub_node_recovery` | `"s3m/sig/migration-pointer/v1"` |
| `AlertEntry` | `pub_node_announce` (en clair dans le payload) | `"s3m/sig/alert-entry/v1"` |

### Tags `key_algorithm`

- Seul le tag **0** (Ed25519 / X25519) est accepté.
- Les tags **1** (ML-DSA / ML-KEM) et **2** (hybride) sont reconnus et
  rejetés par une erreur dédiée « algorithme non supporté », distincte de
  « signature invalide ».
- Un tag inconnu (ex. 255) est rejeté.
- Un tag différent entre l'identité marquée de la preuve VDF
  ([`network.vdf-identity`](vdf-identity.md#identite-marquee)) et
  l'enveloppe est rejeté comme **incohérent**.

## Signature sans exposer les identités

Le Connecteur dérive une paire de signature dédiée au slot User, publiée
auto-certifiante dans l'entrée elle-même (même principe qu'IPNS) :

```
graine de sig_priv_user = KDF(priv_user, "dht-signing", —, pub_user)
```

La sortie de 32 octets est une graine Ed25519 (RFC 8032). La preuve VDF de
l'entrée User porte sur `0x00 ‖ sig_pub_user`. Pour le DispersalManifest,
`sig_priv_dispersal = KDF(K_attach, "dispersal-signing")` — voir
[`crypto.k-attach`](../03-crypto/k-attach.md#portee-de-signature-derivee)
pour le détail de cette dérivation et son asymétrie d'usage.

## Champs publiés par type d'entrée {: #champs-publies }

| Identité | Champs publiés | Durée de vie |
|---|---|---|
| **Node** | IP/port, `timestamp`, preuve VDF, `pub_node_recovery`, `migration_pointer` optionnel, `pub_node_announce` optionnelle, `Encrypt(K_node_self, NodeSnapshotPointer)` | 15 552 000 s, republication toutes les 2 592 000 s |
| **User** | `sig_pub_user`, `timestamp`, preuve VDF, `Encrypt(K_self, UserEntryPlaintext)`. **Pas d'IP/port** : le Connecteur n'accepte aucune connexion entrante | 315 360 000 s |
| **DispersalManifest** | `sig_pub_dispersal` en clair, `timestamp`, `Encrypt(K_attach, DispersalRootPointer)` | 15 552 000 s, republication toutes les 2 592 000 s |
| **EmergencyManifest** (par `user_id`, indépendant du Nœud) | `sig_pub_emergency` en clair, `seq`, `timestamp`, `Encrypt(K_emergency_content, EmergencyManifest)` | 15 552 000 s, **ni republication ni suppression** |
| **Alert** (par clé d'annonce) | `pub_node_announce` en clair, `timestamp`, alerte signée | 15 552 000 s depuis `timestamp`, enveloppe republiée telle quelle toutes les 2 592 000 s |
| **Share** (par partage) | `sig_pub_share` en clair, `seq`, `timestamp`, `Encrypt(K_share_content, SharePointer)` | 15 552 000 s, republication par le propriétaire toutes les 2 592 000 s et à chaque changement |

L'`EmergencyManifest` est écrit par n'importe quel Connecteur du même
`user_id` selon la règle de séquence de
[`protocols.espace-secours`](../04-protocols/espace-secours.md), lu et
réconcilié par n'importe quel Connecteur, intégré mécaniquement par le
Nœud.

### Blobs chiffrés

Chaque champ `Encrypt(…)` est une trame `nonce (12 o, aléatoire) ‖ chiffré ‖
tag` sous la clé indiquée ([`crypto.symmetric-suite`](../03-crypto/symmetric-suite.md)).
Son AAD est `L(libellé AAD du type) ‖ u16be(schema_version)`, où
`schema_version` est la version de protocole
([`deploiement.formats-serialisation`](../07-deploiement/formats-serialisation.md),
valeur 1) :

| Blob | Clé | Libellé AAD |
|---|---|---|
| `NodeSnapshotPointer` | `K_node_self` | `"dht-node-snapshot"` |
| `UserEntryPlaintext` | `K_self` | `"dht-user-plaintext"` |
| `DispersalRootPointer` | `K_attach` | `"dht-dispersal-root"` |
| `EmergencyManifest` | `K_emergency_content` | `"dht-emergency-manifest"` |
| `SharePointer` | `K_share_content` | `"dht-share-pointer"` |

## Rôle de `dispersal_root_partners`

Ce champ n'est pas redondant avec la table
[`dispersal.Partner`](../02-schemas/dispersal/Partner.md) : il résout un
problème d'amorçage. La table `Partner` complète n'est disponible qu'**à
l'intérieur** du contenu chiffré du bloc racine lui-même — pour récupérer ce
tout premier bloc via erasure coding, il faut donc déjà savoir *qui* héberge
ses fragments de parité. D'où la nécessité de publier, dans le
`DispersalRootPointer`, les partenaires du **stripe racine spécifiquement**,
ainsi que le sel du nœud racine (`dispersal_root_salt`, voir
[`crypto.k-dispersal`](../03-crypto/k-dispersal.md)).

## Expiration & republication — trois régimes {: #expiration-et-republication }

Les durées sont des **constantes de protocole en secondes fixes** ;
« 6 mois », « 1 an » et « 10 ans » ne sont que des raccourcis de rédaction :

| Raccourci | Valeur | Secondes |
|---|---|---|
| « 6 mois » | 180 jours | 15 552 000 |
| « 1 an » | 365 jours | 31 536 000 |
| « 10 ans » | 3 650 jours | 315 360 000 |
| période de republication (« mensuelle ») | 30 jours | 2 592 000 |

- **Node et DispersalManifest** : durée de vie de 15 552 000 s, republiées
  à chaque période de 2 592 000 s avec un `timestamp` signé à jour, même
  sans changement de contenu.
- **EmergencyManifest** : durée de vie de 15 552 000 s, **sans
  republication et sans suppression** — elle expire à l'issue de cette
  durée.
- **User** : durée de vie de 315 360 000 s ; republication **réactive** à
  chaque écriture confirmée qui change `fs_root_hash`, et **de secours**
  après 31 536 000 s sans écriture — voir
  [`network.bootstrap`](bootstrap.md) pour l'usage de la comparaison de
  timestamp au chemin rapide.

### Lissage des republications

Pour éviter un pic de charge, chaque republication périodique est décalée :

```
offset_s = entier_big-endian( SHA-256( identifiant ) ) mod 2 592 000
```

- Entrée Node : identifiant = `pub_node` (octets bruts).
- DispersalManifest d'un couple (User, Node) : identifiant =
  `user_id ‖ node_id` (octets bruts, `user_id = pub_user`).
- La republication a lieu aux instants Unix `t` tels que
  `t ≡ offset_s (mod 2 592 000)` — ancrage sur l'époque Unix.

## Rôles réseau et identité libp2p

- **Nœud** : pair Kademlia complet (mode serveur), joignable en TCP (Noise
  + Yamux). Son `PeerId` libp2p dérive de `pub_node`. Il vérifie **tout**
  enregistrement avant de le stocker, qu'il vienne d'un pair ou de lui-même,
  et à nouveau avant de le rendre.
- **Connecteur** : client Kademlia uniquement — aucune adresse d'écoute,
  conformément à l'absence de connexion entrante. Son identité libp2p est
  **éphémère**, tirée au hasard à chaque démarrage, pour que le `PeerId` ne
  relie jamais une session réseau à `pub_user` (décision d'implémentation du
  2026-11-19, `impl/SPEC_GAPS.md`).
- Amorçage provisoire : liste d'adresses de Nœuds en configuration ; le
  mécanisme complet relève de [`network.bootstrap`](bootstrap.md).

## Règles de vérification à la lecture {: #regles-de-verification-a-la-lecture }

Avant de rendre une entrée à l'appelant, `get` vérifie dans l'ordre :
`file_identifier` du payload, tag `key_algorithm`, signature sur les octets
reçus, preuve VDF (Node et User), cohérence du tag entre preuve et
enveloppe, `timestamp` non expiré, et pour `EmergencyEntry` et
`migration_pointer` un `seq` strictement supérieur à celui déjà détenu.
Pour les autres types, une entrée d'horodatage **inférieur** à celui de
l'entrée déjà détenue sous la même clé est refusée (pas de retour en
arrière, pas de résurrection d'une entrée supprimée).
Le déchiffrement AEAD n'est possible qu'avec la clé correspondante.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
