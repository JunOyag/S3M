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

Sous une clé **multi-messages**, la trame d'un message chiffré est :

```
nonce (12 o, en clair) ‖ chiffré ‖ tag (16 o)
```

Sous une clé **à usage unique**, le nonce est le nonce nul (12 octets à
zéro), **implicite** : il n'est pas transmis, la trame est
`chiffré ‖ tag`.

## Politique de nonce

| Cas | Nonce | Borne |
|---|---|---|
| Clé à usage unique (ex. clé de wrap de [`crypto.master-key-chain`](master-key-chain.md)) | Constant, 12 octets à zéro | Nulle : la clé n'est jamais réutilisée, donc aucun risque de réutilisation de nonce |
| Valeurs **non adressées par contenu** sous clé multi-messages (entrées DHT chiffrées sous `K_self` / `K_node_self` / `K_attach`, …) | Aléatoire 12 o (`OsRng`), préfixe en clair | **2^32 messages par clé** — borne documentée, au-delà de laquelle la rotation de clé est obligatoire (probabilité de collision de nonce ≲ 2⁻³³) |
| Valeurs **adressées par contenu** : les blocs (`K_block`, `K_dispersal_block`) | **Synthétique**, déterministe — voir ci-dessous, stocké en préfixe | **~2^48 messages distincts par clé** (borne de collision d'un nonce de 96 bits) |

### Nonce synthétique — blocs adressés par contenu

Un bloc est adressé par son contenu : le chiffrement est donc
**déterministe**, et le nonce est fabriqué plutôt que tiré au sort :

```
nonce = 12 premiers octets de HMAC-SHA256(K_nonce, u32(len(AAD)) ‖ AAD ‖ clair)
```

- **`K_nonce`** : `HKDF-SHA256(K_enc, info = "p2p-storage/synthetic-nonce/v1")`,
  **sans sel** — `K_enc` est la clé de chiffrement de l'usage concerné
  (`K_block`, `K_dispersal_block`, …). Règle générique de la suite.
- **Entrée du HMAC en encodage canonique** (même convention que le KDF,
  u32 gros-boutiste) : `u32(len(AAD)) ‖ AAD ‖ clair` ; l'AAD porte
  l'étiquette de contexte de l'usage (« block », …).
- Le nonce **est transmis** : la trame reste `nonce ‖ chiffré ‖ tag`,
  préfixée par l'en-tête de version de protocole (2 o). Surcoût de trame :
  **30 o** (2 + 12 + 16) — pour un bloc complet de 64 KiO, il reste
  **65 506 o de clair**.
- Sous la même clé, deux messages distincts ont des nonces distincts (collision
  de HMAC négligeable, borne ~2^48) et un même message produit toujours le
  même chiffré — c'est ce qui rend le bloc adressable par son contenu.

> **À faire relire par un cryptographe** : cette politique de nonce
> (dérivation synthétique de `K_nonce`, encodage du HMAC, bornes de
> collision, AAD des blocs) a été arbitrée en spec (`impl/SPEC_GAPS.md`) et
> doit être revue par un cryptographe avant le gel de la suite.

## AAD (associated data)

L'AAD reloye le chiffré à son contexte ; elle n'est **jamais** chiffrée :

```
AAD = en-tête de version (2 o, deploiement.formats-serialisation)
      ‖ étiquette de contexte (domaine : "master-key-wrap", "block", …)
      ‖ champs spécifiques listés sur la page de la clé concernée
```

Pour le **wrap** de `master_key`
([`crypto.master-key-chain`](master-key-chain.md)), les champs sont **les
deux versions** : la version wrappée et la version courante. Toute tentative
de transplanter un wrap d'une version vers une autre échoue alors à la
vérification du tag.

## KDF — HKDF-SHA256

- **HKDF-SHA256, sortie 32 octets** — le KDF de tout le chantier Phase 0
  (`K_attach`, `K_block`, `K_self`, `K_node_self`, `K_dispersal_*`, clé de
  wrap) est ce KDF et rien d'autre.
- **Encodage canonique des entrées multiples** : avant concaténation dans
  `salt`/`info`, chaque composante est préfixée par sa longueur codée sur
  4 octets (ordre gros-boutiste, convention réseau) :
  `len(a) ‖ a ‖ len(b) ‖ b ‖ …`. Deux dérivations aux mêmes composantes mais
  ordonnées différemment produisent donc deux entrées HKDF distinctes — la
  frontière entre composantes ne peut pas être ambiguë.

### Clé de wrap de `master_key[version]`

La clé de wrap `K_wrap`, qui chiffre une clé maîtresse dans une entrée
`wrapped_key` de [`crypto.master-key-chain`](master-key-chain.md), est
dérivée ainsi — aucun KDF plus riche n'est nécessaire puisque la clé wrappée
est à usage unique :

```
K_wrap = HKDF-SHA256(ikm  = master_key[version_courante],
                      salt = ∅,
                      info = encodage canonique("p2p-storage/master-key-wrap/v1"
                                                ‖ u16(version_wrappée)
                                                ‖ u16(version_courante)))
```

- `version_courante` est celle dont dérive `K_wrap`, `version_wrappée` celle
  de la clé maîtresse wrappée ; les deux sont dans l'`info`, donc deux
  dérivations distinctes ne partagent jamais de clé.
- Chiffrement : **ChaCha20-Poly1305**, clé `K_wrap` **à usage unique** —
  nonce nul (12 octets zéro, implicite, voir *Politique de nonce*), trame
  `chiffré ‖ tag`.
- `AAD = en-tête de version (2 o) ‖ "master-key-wrap" ‖ u16(version_wrappée)
  ‖ u16(version_courante)` — toute tentative de transplanter un wrap d'une
  version vers une autre échoue à la vérification du tag.
- `wrapped_key = 48 o` : les 32 o de la clé wrappée chiffrée ‖ le tag de
  16 o (le nonce est implicite, non transmis).

## Registre des étiquettes KDF

Chaque dérivation de clé du protocole porte une **étiquette de domaine** —
le paramètre `info` HKDF-SHA256 ci-dessus, ou le suffixe concaténé pour
les rares dérivées par simple hachage. Ce registre est la **source unique**
des étiquettes ; deux règles :

1. **Unicité globale** : une étiquette n'apparaît qu'une fois dans le
   registre, quel que soit le secret d'entrée, la page qui la définit ou le
   KDF employé. Une étiquette ne sert **jamais** à deux dérivations
   distinctes, même séparées par des secrets différents.
2. **Immuabilité** : une étiquette publiée n'est jamais détournée ni
   réutilisée pour une autre fonction ; toute révision d'une dérivation est
   une nouvelle étiquette versionnée (`…/vN`), donc une nouvelle version de
   protocole.

L'unicité et l'absence de doublon font l'objet d'un test unitaire du noyau
(`impl/core`, `tests/labels.rs`), à créer à la passe code.

### Étiquettes HKDF-SHA256 (paramètre `info`)

| Étiquette | Dérivée | Secret d'entrée | Page définissant la dérivation |
|---|---|---|---|
| *(exception : `info` vide)* | `K_attach` | secret DH X25519 brut | [`crypto.k-attach`](k-attach.md) |
| `"dispersal-signing"` | `sig_priv_dispersal` | `K_attach` | [`crypto.k-attach`](k-attach.md) |
| `"dispersal-content"` | `K_dispersal_content` | `K_attach` | [`crypto.k-dispersal`](k-dispersal.md) |
| `"dispersal-block"` | `K_dispersal_block` | `K_dispersal_content` | [`crypto.k-dispersal`](k-dispersal.md) |
| `"attachment-recovery"` | `K_self` | `priv_user` | [`crypto.k-self`](k-self.md) |
| `"node-recovery"` | `K_node_self` | `priv_node` | [`crypto.k-node-self`](k-node-self.md) |
| `"emergency-content"` | `K_emergency_content` | `K_attach` | [`protocols.espace-secours`](../04-protocols/espace-secours.md) |
| `"emergency-signing"` | `sig_priv_emergency` | `K_attach` | [`protocols.espace-secours`](../04-protocols/espace-secours.md) |
| `"dht-lookup"` | `user_dht_key` | `priv_user` ‖ `pub_user` | [`network.dht-directory`](../01-network-dht/dht-directory.md) |
| `"dht-signing"` | `sig_priv_user` | `priv_user` ‖ `pub_user` | [`network.dht-directory`](../01-network-dht/dht-directory.md) |
| `"p2p-storage/block/v1"` | `K_block` | `master_key[version]` | [`crypto.k-block`](k-block.md) |
| `"p2p-storage/synthetic-nonce/v1"` | `K_nonce` | `K_enc` | cette page |
| `"p2p-storage/master-key-wrap/v1"` | `K_wrap` | `master_key[version_courante]` | cette page ([§ clé de wrap](#cle-de-wrap-de-master_keyversion)) |

- **Exception `K_attach`** : c'est la **seule** dérivation dont l'entrée soit
  le secret DH brut ; son `info` vide **ne vaut que pour la v1 X25519** et
  **aucune autre dérivation ne
  prend le secret DH en entrée** — le reste part toujours d'une clé déjà
  étiquetée (y compris `sig_priv_dispersal` et les clés d'espace de secours,
  dérivées de `K_attach` et non du secret brut). Les variantes
  post-quantiques de cette même dérivation
  ([`agilite.k-attach-kem`](../08-agilite-crypto/k-attach-kem.md),
  [`agilite.tag-hybride`](../08-agilite-crypto/tag-hybride.md)) ne portent
  **pas** cette étiquette vide : elles recevront une étiquette **versionnée
  portant l'identifiant d'algorithme** (p. ex. `…/v2/<alg-id>`), à trancher
  à leur passe.
- Les préfixes `p2p-storage/` sont **réservés** aux dérivations nouvelles :
  une étiquette sans préfixe est héritée du vocabulaire initial du chantier
  Phase 0 et reste inchangée.

### Contextes d'AAD (registre distinct)

Les étiquettes de contexte `AAD` forment un **registre séparé** du registre
des étiquettes `info` ci-dessus : mêmes règles d'unicité et d'immuabilité,
mais elles qualifient un *chiffré* (elles entrent dans l'AAD), pas une
*dérivation*. Rappel de la forme générale (voir § AAD plus haut) :

```
AAD = en-tête de version (2 o) ‖ contexte ‖ champs spécifiques
```

| Contexte | Chiffré / clé | Champs spécifiques après le contexte | Page |
|---|---|---|---|
| `"master-key-wrap"` | `wrapped_key` / `K_wrap` | `u16(version_wrappée)` ‖ `u16(version_courante)` | cette page ([§ clé de wrap](#cle-de-wrap-de-master_keyversion)) |
| `"block"` | blocs / `K_block`, `K_dispersal_block` | aucun (chiffrement déterministe : deux écritures identiques → même AAD → même chiffré) | [`crypto.k-block`](k-block.md) |
| contextes par clé | chaque autre valeur chiffrée (`K_self`, `K_node_self`, `K_attach`, `K_emergency_content`, …) | listés sur la page de la clé concernée | page de la clé |

### Dérivées par simple hachage (hors KDF)

Le hachage de clé n'est pas un KDF, mais la même règle d'unicité
s'applique aux étiquettes concaténées :

| Dérivation | Produit | Page |
|---|---|---|
| `H(K_attach)` | `dht_key` du DispersalManifest | [`network.dht-directory`](../01-network-dht/dht-directory.md) |
| `H(K_attach ‖ "emergency")` | `emergency_dht_key` | [`protocols.espace-secours`](../04-protocols/espace-secours.md) |

`H(pub_key)` (challenge VDF, tag hybride) n'est **pas** une dérivation de
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

- **Aucune formule de dérivation de clé de bloc** : `K_block` et
  `K_dispersal_block` relèvent de leurs pages respectives
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
