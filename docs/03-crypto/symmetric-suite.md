---
id: crypto.symmetric-suite
kind: narrative
title: "Suite cryptographique symétrique (AEAD, KDF, hash)"
section: "§3.8"
status: draft
verified_by: []
---

# Suite cryptographique symétrique (AEAD, KDF, hash)

Cette page fixe l'**unique** suite cryptographique symétrique du protocole :
la primitive AEAD, le KDF de dérivation de clés et le hash de contenu. Les
pages de clés ([`crypto.k-attach`](k-attach.md), [`crypto.k-block`](k-block.md),
[`crypto.k-dispersal`](k-dispersal.md), [`crypto.k-self`](k-self.md),
[`crypto.k-node-self`](k-node-self.md),
[`crypto.master-key-chain`](master-key-chain.md)) n'instantient pas leur
propre primitive : elles décrivent quoi chiffrer et avec quelle clé, et
renvoient ici pour le comment.

## AEAD — ChaCha20-Poly1305

Clé de 32 octets, nonce de 12 octets, tag d'authentification de 16 octets.
Un seul code AEAD sert tout le protocole (blocs, blobs DHT, wrap).

Trame d'une valeur chiffrée dont le nonce est **transmis** :

```
nonce (12 o, en clair) ‖ chiffré ‖ tag (16 o)
```

Pour un bloc de données, cette trame est précédée de l'en-tête de version
(2 o) — voir [`crypto.k-block`](k-block.md). Sous une clé **à usage unique**
dont le nonce est **implicite** (nonce nul, 12 octets à zéro, non transmis),
la trame est `chiffré ‖ tag`.

## Politique de nonce

| Cas | Nonce | Borne |
|---|---|---|
| Clé de wrap `K_wrap` ([§ clé de wrap](#cle-de-wrap-de-master_keyversion)) | Nul, implicite | Nulle : un seul message par clé |
| Blocs (`K_block`, `K_dispersal_block`) | Aléatoire 12 o (CSPRNG), transmis | **Un seul message par clé** : une clé par sel neuf (et, pour `K_block`, par position) — le nonce aléatoire n'est qu'une défense en profondeur contre une réutilisation accidentelle de sel |
| Blobs DHT (`K_self`, `K_node_self`, `K_attach`, `K_emergency_content`) | Aléatoire 12 o (CSPRNG), transmis | Un message par publication ou republication : de l'ordre de quelques milliers sur toute la vie d'une identité |

**Borne d'usage des clés AEAD.** Aucune clé de ce protocole ne chiffre un
nombre de messages proche de la limite usuelle de 2^32 pour un nonce
aléatoire de 96 bits. **Aucun compteur persistant n'est donc spécifié** : un
compteur local ne serait pas reconstructible depuis la seule seed
([`deploiement.disaster-recovery`](../07-deploiement/disaster-recovery.md))
et n'apporterait qu'une fausse assurance après restauration.

!!! note "Nonce synthétique — retiré en V3"
    La V2 chiffrait les blocs en déterministe, sous une clé par élément, avec
    un nonce synthétique (HMAC du clair). La V3 dérive une clé par sel neuf
    et par position ([`crypto.k-block`](k-block.md),
    [`crypto.k-dispersal`](k-dispersal.md)) : chaque clé de bloc ne chiffre
    qu'un message ; le nonce synthétique et son étiquette disparaissent, et
    avec eux la revue cryptographique qu'ils exigeaient. Arbitrage du
    2026-11-19 (`impl/SPEC_GAPS.md`).

## AAD (associated data)

L'AAD relie le chiffré à son contexte ; elle n'est **jamais** chiffrée.

| Chiffré | AAD |
|---|---|
| Bloc de données ou bloc d'index | en-tête de version (2 o, [`deploiement.formats-serialisation`](../07-deploiement/formats-serialisation.md)) |
| Blob DHT | `L(libellé AAD du type)` ‖ `u16be(schema_version)` — libellés listés sur [`network.dht-directory`](../01-network-dht/dht-directory.md) |
| `wrapped_key` | en-tête de version (2 o) ‖ `"master-key-wrap"` ‖ `u16(version_wrappée)` ‖ `u16(version_courante)` |

Pour les blocs, l'en-tête suffit : la clé ne sert qu'à un message et porte
déjà toute la séparation de domaine. Pour le **wrap**, les deux versions dans
l'AAD font échouer toute transplantation d'un wrap d'une version vers une
autre ; l'en-tête de version n'entre que dans l'AAD et n'est pas repris en
préfixe de la valeur stockée `wrapped_key` (48 o, sans en-tête).

## KDF — HKDF-SHA256

**Toute dérivation `KDF(…)` de la spécification est un HKDF-SHA256
(RFC 5869)** instancié ainsi :

```
KDF(secret, label, [salt], [entrées publiques…]) :=
  HKDF( IKM  = secret,
        salt = salt, ou chaîne vide s'il n'y en a pas,
        info = "s3m/kdf/v1" ‖ L(label) ‖ L(entrée_1) ‖ L(entrée_2) ‖ …,
        longueur de sortie = 32 octets )

L(x) = longueur de x sur 4 octets big-endian, suivie de x
```

- Le **secret** est toujours l'IKM, seul ; les entrées publiques
  (`pub_user`, index de bloc, versions…) vont dans `info`, **jamais** dans
  l'IKM.
- Le préfixe `"s3m/kdf/v1"` est écrit brut (sans longueur), une
  seule fois, en tête de chaque `info` : il sépare les dérivations de ce
  protocole de tout autre usage de HKDF sur les mêmes secrets.
- L'encodage `L(·)` rend les frontières non ambiguës : deux dérivations aux
  mêmes composantes ordonnées différemment produisent deux `info` distincts.
- Les entiers sont encodés en big-endian à largeur fixe (`u16`, `u32`) avant
  d'être passés à `L(·)`.
- La sortie de 32 octets sert directement de clé symétrique, ou de **graine
  Ed25519** (forme RFC 8032) pour les clés de signature.

### Clé de wrap de `master_key[version]`

```
K_wrap = KDF(master_key[version_courante], "master-key-wrap", —,
             u16(version_wrappée), u16(version_courante))
```

- Les deux versions sont des entrées publiques : deux couples distincts ne
  partagent jamais de clé, et chaque `K_wrap` ne chiffre qu'**un** message.
- Chiffrement ChaCha20-Poly1305 sous nonce nul implicite, trame
  `chiffré ‖ tag` : `wrapped_key = 48 o` (32 o chiffrés ‖ tag de 16 o).
- AAD : voir le tableau ci-dessus. Mécanisme de chaîne :
  [`crypto.master-key-chain`](master-key-chain.md).

## Registre des étiquettes KDF

Chaque dérivation porte une **étiquette** (`label` de la convention). Ce
registre est la **source unique** des étiquettes ; deux règles :

1. **Unicité globale** : une étiquette n'apparaît qu'une fois, quel que soit
   le secret d'entrée ou la page qui la définit.
2. **Immuabilité** : une étiquette publiée n'est jamais détournée vers une
   autre fonction. Une révision de la convention elle-même change le préfixe
   (`"s3m/kdf/v2"`), donc la version de protocole.

L'unicité fait l'objet d'un test unitaire du noyau (`impl/core`,
`tests/labels.rs`).

| Étiquette | Dérivée | Secret (IKM) | Sel | Entrées publiques | Page |
|---|---|---|---|---|---|
| `"attach"` | `K_attach` | secret partagé X25519 | sel d'attachement | — | [`crypto.k-attach`](k-attach.md) |
| `"dispersal-signing"` | graine de `sig_priv_dispersal` | `K_attach` | — | — | [`crypto.k-attach`](k-attach.md) |
| `"dispersal-content"` | `K_dispersal_content` | `K_attach` | — | — | [`crypto.k-dispersal`](k-dispersal.md) |
| `"dispersal-block"` | `K_dispersal_block` | `K_dispersal_content` | sel du nœud d'index | — | [`crypto.k-dispersal`](k-dispersal.md) |
| `"emergency-content"` | `K_emergency_content` | `K_attach` | — | — | [`protocols.espace-secours`](../04-protocols/espace-secours.md) |
| `"emergency-signing"` | graine de `sig_priv_emergency` | `K_attach` | — | — | [`protocols.espace-secours`](../04-protocols/espace-secours.md) |
| `"attachment-recovery"` | `K_self` | `priv_user` | — | — | [`crypto.k-self`](k-self.md) |
| `"node-recovery"` | `K_node_self` | `priv_node` | — | — | [`crypto.k-node-self`](k-node-self.md) |
| `"dht-lookup"` | `user_dht_key` | `priv_user` | — | `pub_user` | [`network.dht-directory`](../01-network-dht/dht-directory.md) |
| `"dht-signing"` | graine de `sig_priv_user` | `priv_user` | — | `pub_user` | [`network.dht-directory`](../01-network-dht/dht-directory.md) |
| `"element"` | `K_elem` (clé d'élément) | `master_key[version]` | `encryption_salt` | — | [`crypto.k-block`](k-block.md) |
| `"block"` | `K_block` | `K_elem` | — | `u32(index_du_bloc)` | [`crypto.k-block`](k-block.md) |
| `"child-wrap"` | `K_child_wrap` (clés des enfants d'un répertoire) | `K_elem` du répertoire | — | — | [`protocols.partage`](../04-protocols/partage.md#cles-element) |
| `"share-content"` | `K_share_content` | secret du partage `S` | — | — | [`protocols.partage`](../04-protocols/partage.md#cles) |
| `"share-signing"` | graine de `sig_priv_share` | `priv_user` | — | `share_id` | [`protocols.partage`](../04-protocols/partage.md#cles) |
| `"share-invite"` | clé de l'invitation d'un Utilisateur S3m | secret partagé X25519 (éphémère × destinataire) | — | clé publique éphémère | [`protocols.partage`](../04-protocols/partage.md#destinataire) |
| `"master-key-wrap"` | `K_wrap` | `master_key[version_courante]` | — | `u16(version_wrappée)`, `u16(version_courante)` | cette page |
| `"node-snapshot"` | `K_node_snapshot` (blocs du snapshot du NodeManifest) | `priv_node` | sel du snapshot (16 o) | `u32(index_du_bloc)` | [`deploiement.disaster-recovery`](../07-deploiement/disaster-recovery.md#snapshot) |
| `"admin-totp"` | secret TOTP de l'administration à distance (20 premiers octets) | `priv_node` | — | `u32(numéro_de_série)` | [`deploiement.appairage-admin`](../07-deploiement/appairage-admin.md#administration) |
| `"connector-auth"` | preuve d'authentification Connecteur → Nœud | `K_attach` | — | `PeerId` du Connecteur, `PeerId` du Nœud | [`protocols.echange-blocs`](../04-protocols/echange-blocs.md) |

- `K_attach` n'est plus une exception : la V2 lui donnait un `info` vide, la
  V3 lui attribue l'étiquette `"attach"`. Les variantes post-quantiques
  ([`agilite.k-attach-kem`](../08-agilite-crypto/k-attach-kem.md),
  [`agilite.tag-hybride`](../08-agilite-crypto/tag-hybride.md)) recevront
  leur propre étiquette portant l'identifiant d'algorithme, à leur passe.
- `"master-key-wrap"` est aussi un contexte d'AAD : les deux registres sont
  distincts (l'un qualifie une dérivation, l'autre un chiffré), la
  coïncidence est sans effet.
- `priv_node_recovery` n'a **pas** d'étiquette KDF : c'est un chemin
  SLIP-0010 durci ([`crypto.identity-derivation`](identity-derivation.md)),
  comme les autres identités — la ligne « `node-recovery-signing` » du
  document de modifications V3 est écartée au profit de cette dérivation
  déjà arbitrée.
- Étiquettes retirées en V3, jamais réutilisables :
  `"s3m/block/v1"`, `"s3m/synthetic-nonce/v1"`,
  `"s3m/master-key-wrap/v1"`.

### Dérivées par simple hachage (hors KDF)

Ces clés de recherche DHT sont des hachages publics d'un secret, hors
convention KDF (inchangés depuis la V2) :

| Dérivation | Produit | Page |
|---|---|---|
| `SHA-256(K_attach)` | `dht_key` du DispersalManifest | [`network.dht-directory`](../01-network-dht/dht-directory.md) |
| `SHA-256(K_attach ‖ "emergency")` | `emergency_dht_key` | [`protocols.espace-secours`](../04-protocols/espace-secours.md) |
| `SHA-256(L("s3m/share-id") ‖ S)` | `share_id` d'un partage | [`protocols.partage`](../04-protocols/partage.md#cles) |
| `SHA-256(sig_pub_share ‖ "share")` | clé de l'annuaire d'un partage | [`protocols.partage`](../04-protocols/partage.md#cles) |

`SHA-256(identité marquée)` (challenge VDF) n'est **pas** une dérivation de
clé : hors registre.

### Hors registre — chemins SLIP-0010

Les dérivations d'identités (`priv_user`, `priv_node`, clé de secours,
`master_key[version]`) ne portent pas d'étiquette KDF : ce sont des
chemins SLIP-0010 durcis, définis — avec la table des rôles — sur
[`crypto.identity-derivation`](identity-derivation.md), page de référence
non recopiée ici.

## Hash de contenu — SHA-256

Le hash d'intégrité de contenu (challenges PoS, comparaison `block_hash` en
lecture, empreintes de blocs) est **SHA-256** — confirmé, et cette page est
le seul endroit de la spécification qui le fixe.

## Version de protocole

Il n'y a **pas de table d'identifiants d'algorithme dédiée** : la **version
de protocole 1 = cette suite exacte** (ChaCha20-Poly1305 + HKDF-SHA256 +
SHA-256). La table *version de protocole → suite* vit sur
[`deploiement.formats-serialisation`](../07-deploiement/formats-serialisation.md) ;
toute révision de la suite est une nouvelle version de protocole.

Côté quantique, aucune révision n'est à prévoir pour ces primitives :
l'ordinateur quantique ne donne qu'un avantage Grover (doublement effectif
de la taille de clé), géré par une révision de version si besoin — la
migration post-quantique du protocole porte sur les signatures et l'échange
de clés, voir [`agilite.kem-vs-nike`](../08-agilite-crypto/kem-vs-nike.md).

## Ce que cette page ne dit pas

- **Aucune règle propre à une clé** : `K_block` et `K_dispersal_block`
  appliquent la convention ci-dessus mais relèvent de leurs pages
  respectives
  ([`crypto.k-block`](k-block.md), [`crypto.k-dispersal`](k-dispersal.md)).
- **Aucune procédure de rotation** : voir
  [`crypto.master-key-chain`](master-key-chain.md) et
  [`crypto.identity-derivation`](identity-derivation.md) pour les rôles et
  chemins de dérivation.

## Références

- `crypto.key-hierarchy` — Hiérarchie des Clés — Vue d'ensemble
- `crypto.master-key-chain` — Continuité de Chiffrement — master_key_chain
- `crypto.k-block` — K_block — Contenu Réel des Blocs
- `crypto.k-attach` — K_attach — Métadonnées de Dispersion
- `crypto.k-dispersal` — K_dispersal_content / K_dispersal_block
- `crypto.k-self` — K_self — Récupération depuis la Seed
- `crypto.k-node-self` — K_node_self — Confidentialité de la Cartographie Nœud
- `crypto.identity-derivation` — Dérivation des Identités — BIP-39 → SLIP-0010
- `deploiement.formats-serialisation` — Formats de Sérialisation et Performance
- `agilite.kem-vs-nike` — Contrainte Structurelle : un KEM n'est pas un NIKE
- `overview.architecture` — Vue d'ensemble & Architecture Globale

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
