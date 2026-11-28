---
id: protocols.echange-blocs
kind: narrative
title: "Protocole d'Échange de Blocs"
section: "§3.7, §3.12"
status: draft
verified_by: []
---

# Protocole d'Échange de Blocs

Transport des blocs, fragments de parité, challenges et avis de suppression
entre Connecteur, Nœud et partenaires. Fonctionnalité ajoutée le
2026-11-20 (entrée « Protocole d'échange de blocs » de `impl/SPEC_GAPS.md`) :
la spec décrivait *ce qui* circule — voir
[`protocols.dispersion-transactionnelle`](dispersion-transactionnelle.md),
[`protocols.acces-applicatif`](acces-applicatif.md),
[`securite.pos-challenges`](../05-securite/pos-challenges.md),
[`protocols.tombstones`](tombstones.md) — sans dire *comment*.

## Transport

- Même pile libp2p que la DHT
  ([`network.dht-directory`](../01-network-dht/dht-directory.md#roles-reseau-et-identite-libp2p)) :
  TCP + Noise + Yamux. Le `PeerId` d'un Nœud est dérivé de `pub_node`, celui
  du Connecteur est éphémère.
- Protocole **requête/réponse** `/s3m/blocks/1` : une requête
  [`network.BlockRequest`](../02-schemas/network/BlockRequest.md) et une
  réponse [`network.BlockResponse`](../02-schemas/network/BlockResponse.md)
  par flux, chacune préfixée de sa longueur (`u32be`).
- Taille maximale d'un message : **1 048 576 o** (un bloc de 65 536 o et ses
  en-têtes tiennent largement) ; au-delà, `TooLarge` sans lecture du corps.
- Champ `version` = 1 ; toute autre valeur ⇒ `Malformed`.
- QoS : les `Challenge` ne sont jamais soumis au bridage de bande passante
  ([`securite.pos-challenges`](../05-securite/pos-challenges.md)).

## Qui envoie quoi

| Émetteur → destinataire | Requêtes | Identifiant (`credential`) |
|---|---|---|
| Connecteur → son Nœud | `GetBlock`, `PutBlock`, `CommitRoot`, `ReportIncident`, `RenewGrant` | `UserCredential` |
| Connecteur → nouveau Nœud | `Delegate` | `UserCredential` (attachement au nouveau Nœud) |
| Nœud → partenaire | `StoreFragment`, `Challenge`, `FetchFragment`, `Tombstone` | aucun : identité Noise du Nœud |
| Connecteur → partenaire (Nœud injoignable) | `FetchFragment` seulement | `RescueCredential` |
| Nouveau Nœud → partenaire de l'ancien | `FetchFragment` seulement | `DelegatedCredential` |
| Connecteur → partenaire de secours | `EmergencyPut` | `EmergencyCredential` |
| Tout pair → partenaire de secours | `EmergencyGet`, `EmergencyRelease` | aucun (voir [`protocols.espace-secours`](espace-secours.md#depot)) |

Corps des requêtes :

```
--8<-- "network/GetBlock.table.md"
```
```
--8<-- "network/PutBlock.table.md"
```
```
--8<-- "network/CommitRoot.table.md"
```
```
--8<-- "network/ReportIncident.table.md"
```
```
--8<-- "network/RenewGrant.table.md"
```
```
--8<-- "network/Delegate.table.md"
```
```
--8<-- "network/StoreFragment.table.md"
```
```
--8<-- "network/Challenge.table.md"
```
```
--8<-- "network/FetchFragment.table.md"
```
```
--8<-- "network/Tombstone.table.md"
```

## Authentification

Les `PeerId` ci-dessous sont les octets du `PeerId` libp2p (encodage
multihash), authentifiés par la poignée de main Noise. Lier chaque preuve
aux deux identités de la connexion suffit à empêcher sa réutilisation par un
tiers : il n'a pas la clé privée de l'identité Noise liée.

### Connecteur → Nœud

```
--8<-- "network/UserCredential.table.md"
```

`proof = KDF(K_attach, "connector-auth", —, peer_connecteur, peer_noeud)`
(étiquette du registre de
[`crypto.symmetric-suite`](../03-crypto/symmetric-suite.md#registre-des-etiquettes-kdf)).
Le Nœud retrouve l'Utilisateur rattaché par `user_id` (= `pub_user`, déjà
connu de lui dans [`node.AttachedUser`](../02-schemas/node/AttachedUser.md),
jamais visible d'un tiers sous Noise), recalcule `K_attach`
([`crypto.k-attach`](../03-crypto/k-attach.md)) et compare à temps constant.
Un appareil non rattaché est refusé (`Unauthorized`).

### Entre Nœuds partenaires

Aucun identifiant : le `PeerId` Noise *est* `pub_node`. Un partenaire ne
répond qu'aux Nœuds avec lesquels il a un compte de troc
([`node.PartnerAccount`](../02-schemas/node/PartnerAccount.md)), et ne sert
ou ne libère que les fragments qu'il héberge **pour ce Nœud**.

- `StoreFragment` → `FragmentReceipt` : signature Ed25519 du partenaire sur
  `L("s3m/sig/fragment-receipt/v1") ‖ hash ‖ node_id_déposant`. Seul
  un reçu valide compte parmi les k+2 confirmations de la dispersion.
- `Challenge` → `ChallengeResponse` : `SHA-256(fragment ‖ nonce)` ; un
  `FetchFragment` adressé à un partenaire vaut lui aussi challenge.
- `Tombstone` porte l'avis signé de
  [`protocols.tombstones`](tombstones.md) ; `Ack.freed` = nombre de blocs
  libérés ; un avis non plus récent ⇒ `Replayed`.

### Autorisation de secours {: #autorisation-de-secours }

Un partenaire ne connaît pas les Utilisateurs. Pour qu'un Connecteur puisse
lire la parité quand son Nœud est injoignable
([chemin de secours](acces-applicatif.md#chemin-de-secours)) sans ouvrir les
partenaires à n'importe qui, le Nœud lui délivre une
[`network.RescueGrant`](../02-schemas/network/RescueGrant.md) :

1. Le Connecteur tire une clé Ed25519 **anonyme** (`grant_priv`, propre à
   l'appareil, jamais dérivée de l'identité User) et envoie `RenewGrant`.
   Le Nœud répond `GrantIssued` : une autorisation signée valable
   **15 552 000 s** (6 mois). Le Connecteur la renouvelle à chaque
   connexion où il reste moins de la moitié de cette durée.
2. Nœud injoignable : le Connecteur présente `RescueCredential` — l'autorisation et
   une signature de `grant_priv` sur
   `L("s3m/sig/rescue-session/v1") ‖ L(peer_demandeur) ‖ L(peer_partenaire)`.
3. Le partenaire vérifie l'autorisation (signature de l'émetteur, expiration)
   puis la preuve de session ; il ne sert que les fragments qu'il héberge
   pour un Nœud que l'autorisation **couvre** (voir ci-dessous).

```
--8<-- "network/RescueCredential.table.md"
```

**Débit** : au plus **64 `FetchFragment` par seconde et par `grant_pub`**
(rafale 256), sinon `RateLimited` ; une autorisation non vérifiable est
rejetée par une simple vérification de signature, avant tout accès disque.
Les fragments étant chiffrés et indexés par Nœud et non par Utilisateur,
un Utilisateur autorisé peut lire des fragments d'autres Utilisateurs du même
Nœud : ils restent indéchiffrables pour lui (compromis accepté).

#### Nœud couvert

| L'autorisation est émise par… | Elle couvre les fragments de… |
|---|---|
| le Nœud `O`, sans pointeur de migration valide sur `O` | `O` |
| le Nœud `O`, **avec** un pointeur de migration valide sur `O` | rien : **révoquée** (la clé de `O` a pu fuiter) |
| le Nœud `N`, listant `O` dans `covered_node_ids` | `N`, et `O` seulement si la DHT porte un pointeur valide `O → N` |

Le pointeur est un
[`network.SignedMigrationPointer`](../02-schemas/network/SignedMigrationPointer.md)
signé par `priv_node_recovery`, que le partenaire **lit et vérifie lui-même
dans la DHT** — jamais une copie fournie par le demandeur. Pendant la
migration, l'autorisation émise par le nouveau Nœud porte donc les deux
identités ([`securite.incidents-compromissions`](../05-securite/incidents-compromissions.md)).

### Délégation au nouveau Nœud (perte du Nœud) {: #delegation }

Si l'ancien Nœud est perdu **avec sa seed** (aucun pointeur de migration
possible), le Connecteur, qui pilote seul la migration
([`protocols.migration-noeud`](migration-noeud.md)), délègue son
autorisation au nouveau Nœud :

```
--8<-- "network/DelegatedCredential.table.md"
```

Il l'envoie au nouveau Nœud par `Delegate` ; celui-ci la présente aux
partenaires de l'ancien pour ses `FetchFragment`. Le partenaire vérifie la
chaîne : autorisation valide et couvrant le Nœud propriétaire, signature de
délégation par `grant_pub`, `expires_at` non dépassé et au plus celui de
l'autorisation, `PeerId` du demandeur = `delegate_node_id`. Aucune clé de
l'ancien Nœud n'est nécessaire.

## Conservation des fragments d'un Nœud silencieux

Un partenaire conserve les fragments d'un Nœud qui ne le contacte plus
pendant **au moins 15 552 000 s** (6 mois) après le dernier échange — même
durée que l'entrée DHT `DispersalManifest` et que l'autorisation de
secours, afin que la migration reste possible pendant toute cette fenêtre.
Au-delà, les données ne sont plus garanties (limite résiduelle de
[`protocols.migration-noeud`](migration-noeud.md#limite-residuelle)).

## Réponses et erreurs

```
--8<-- "network/BlockResponse.table.md"
```

| Requête | Réponse en cas de succès |
|---|---|
| `GetBlock`, `FetchFragment` | `BlockData` — le demandeur recalcule le hash ([`protocols.integrite-lecture`](integrite-lecture.md)) |
| `PutBlock` | `Stored` (`hash = SHA-256(data)`) |
| `CommitRoot` | `RootState` : `committed = true` si `base_root` est la racine courante, sinon `false` et la racine courante (conflit, [`protocols.write-queue`](write-queue.md)) ; toujours le quota et l'occupation de l'Utilisateur |
| `StoreFragment` | `FragmentReceipt` |
| `Challenge` | `ChallengeResponse` |
| `ReportIncident`, `Delegate`, `Tombstone`, `EmergencyRelease` | `Ack` |
| `EmergencyPut` | `Stored` |
| `EmergencyGet` | `BlockData` |
| `RenewGrant` | `GrantIssued` |
| `ReleaseBlocks` | `Ack` (`freed` : blocs libérés) |
| `ListBlocks` | `BlockList` |

`RootState.quota_bytes` / `used_bytes` (ajout du 2026-11-21 ; 0 : non
communiqué par un Nœud plus ancien) donnent la taille du lecteur monté et
l'espace affiché par le Connecteur. Un `CommitRoot` dont
`new_root = base_root` ne change rien : il sert à lire cet état.

### Descripteur de racine {: #descripteur-de-racine }

Ajout du 2026-11-25. `CommitRoot.root_seal` porte le descripteur scellé de
`new_root` ([`crypto.k-self#k-root`](../03-crypto/k-self.md#k-root)), que le
Nœud garde avec la racine et renvoie dans `RootState.current_root_seal`.
Règles du Nœud, à une racine validée : descripteur fourni → il remplace le
précédent ; absent et racine inchangée (lecture) → le précédent est gardé ;
absent et racine changée (Connecteur plus ancien) → effacé, jamais de
descripteur périmé. Une lecture `0 → 0` d'un appareil sans racine ne
consomme pas l'adoption d'un Utilisateur restauré ou repris. Le Connecteur
sans sel connu pour la racine courante (appareil neuf, autre appareil
après un conflit) ouvre le descripteur reçu avant de recourir à l'entrée
User. Le descripteur figure aussi dans le snapshot du Nœud
(`AttachedUser.root` / `root_seal`,
[`deploiement.disaster-recovery`](../07-deploiement/disaster-recovery.md)).

Toute erreur est une `Failure` portant un `ErrorCode`. Un partenaire qui
répond `NotFound` à un `FetchFragment` ou `Challenge` portant sur un fragment
qu'il doit héberger est traité comme un échec PoS
([`securite.blacklist-fraude`](../05-securite/blacklist-fraude.md)).

## Libération des blocs d'un Utilisateur {: #liberation }

Ajout du 2026-11-23 (arbitrage `impl/SPEC_GAPS.md`). Les blocs d'un
Utilisateur sont immuables (copie sur écriture) : sans libération, chaque
modification consomme du quota pour toujours.

- **`ReleaseBlocks`** (Connecteur → son Nœud, `UserCredential`) : au plus
  2 048 hashes. Envoyée seulement après un `CommitRoot` confirmé, pour les
  blocs de l'ancienne racine que la nouvelle ne référence plus
  ([`protocols.ecriture-differee`](ecriture-differee.md#ordre-denvoi-et-de-suppression)).
  Le Connecteur garde la liste jusqu'à l'accusé et la renvoie après une
  interruption ; la requête est idempotente.
- Le Nœud ne considère que les blocs de **cet** Utilisateur (`UserBlock`
  dont il est propriétaire) ; un hash inconnu, étranger ou déjà libéré est
  ignoré. Pour chaque bloc libéré, il **rend le quota aussitôt**
  (`used_bytes`) et note l'instant de libération. Le bloc reste lisible
  pendant un **délai de 24 h** (un autre appareil resté sur l'ancienne
  racine peut encore la lire). Si l'Utilisateur a encore des versions
  passées, ce délai passe à la **durée de conservation de l'historique**
  (ajout du 2026-11-28) : une libération ne peut pas effacer des versions
  plus tôt qu'une purge, protégée par le 2FA
  ([`securite.incidents-compromissions#2fa`](../05-securite/incidents-compromissions.md#2fa)).
  Ensuite :
    - bloc en attente de dispersion : retiré de la file et effacé ;
    - bloc d'un stripe : effacé quand **tous** les blocs réels du stripe
      sont libérés et leur délai échu ; le stripe est alors retiré et ses
      fragments purgés chez les partenaires par
      [`protocols.tombstones`](tombstones.md) (les contrôles PoS
      recalculent la parité depuis les blocs locaux : un stripe
      partiellement libéré les garde).
- Un `PutBlock` d'un bloc libéré mais pas encore effacé l'annule (le bloc
  sert de nouveau) et le recompte dans le quota.
- **`ListBlocks`** (Connecteur → son Nœud, `UserCredential`) : blocs de
  l'Utilisateur encore comptés, par hash croissant et par pages
  (`after`, `limit` ≤ 2 048). Sert au **rattrapage manuel** des versions
  accumulées avant cette fonctionnalité : le Connecteur liste ses blocs,
  retire ceux qu'atteint sa racine courante, et libère le reste par
  `ReleaseBlocks`. Geste confirmé par l'Utilisateur dans le tableau de bord
  (un autre appareil qui écrit au même moment pourrait perdre des blocs
  pas encore validés).

## Partenariats et rattachements automatiques

`Probe`, `ProposePartnership` et `Attach` (ajouts du 2026-11-20) : voir
[`protocols.partenariat-automatique`](partenariat-automatique.md).

## Import d'un volume

`OwnershipQuery` (ajout du 2026-11-20), Nœud → partenaire : voir
[`protocols.gestion-volumes`](gestion-volumes.md#ownership-query).

## Espace de secours

`EmergencyPut`, `EmergencyGet` et `EmergencyRelease` (ajouts du
2026-11-21) : voir [`protocols.espace-secours`](espace-secours.md#depot).

## Partage

`ShareCredential` (lecture des blocs d'un propriétaire sur autorisation
signée) et `RevokeShare` (ajouts du 2026-11-22) : voir
[`protocols.partage`](partage.md#lecture).

## Canal Nœud ↔ Utilisateurs

`ReadMessages` et `PostMessage` (ajouts du 2026-11-21) : voir
[`protocols.canal-noeud`](canal-noeud.md#requetes).

## Hors périmètre

Traversée de NAT ([`network.bootstrap`](../01-network-dht/bootstrap.md)) et
ordres de migration entre Nœuds : ils réutiliseront ce transport et ces
identifiants.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
