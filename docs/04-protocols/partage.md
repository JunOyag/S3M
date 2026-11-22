---
id: protocols.partage
kind: narrative
title: "Partage de Fichiers et de Dossiers"
section: "§3.12.6"
status: draft
verified_by: []
---

# Partage de Fichiers et de Dossiers

Fonctionnalité ajoutée le 2026-11-22. Un propriétaire confie **en lecture**
un fichier, ou un dossier avec toute son arborescence, à un Utilisateur
S3m désigné ou par un lien S3m. Le partage ne révèle **ni la clé maîtresse
ni aucune clé hors de l'élément partagé**, et suit les modifications de
l'élément. Étapes suivantes, hors de cette page : espace partagé en
écriture (droits de modification et de suppression, Utilisateurs S3m
seulement), menu contextuel de l'Explorateur, accès depuis un navigateur.

## Clés d'élément {: #cles-element }

Chaque version d'un fichier ou d'un répertoire a sa clé d'élément,
dérivée de la clé maîtresse ; les clés de ses blocs en dérivent
([`crypto.k-block`](../03-crypto/k-block.md)) :

```
K_elem  = KDF(master_key[version], "element", encryption_salt)
K_block = KDF(K_elem, "block", —, u32(index_du_bloc))
```

Chaque entrée d'un répertoire ([`fs.DirectoryEntry`](../02-schemas/fs/DirectoryEntry.md))
porte la clé d'élément de l'enfant, chiffrée sous celle du répertoire :

```
K_child_wrap = KDF(K_elem du répertoire, "child-wrap")
wrapped_key  = Encrypt(K_child_wrap, K_elem de l'enfant)   // 12 + 32 + 16 = 60 o
AAD          = L("s3m/child-key") ‖ encryption_salt de l'enfant
```

Qui détient la clé d'un répertoire lit donc toute son arborescence, et
rien d'autre ; le propriétaire, lui, redérive tout de la clé maîtresse.
Ce changement de dérivation n'est pas rétrocompatible : il a été accepté
le 2026-11-22, le projet n'étant pas en production.

## Secret et clés d'un partage {: #cles }

Un partage = un destinataire (ou un lien) ; chacun a son secret `S`
(32 o d'un CSPRNG), tiré à la création :

| Valeur | Dérivation | Usage |
|---|---|---|
| `share_id` | `SHA-256(L("s3m/share-id") ‖ S)` | identifiant connu du Nœud (autorisation, retrait) |
| `K_share_content` | `KDF(S, "share-content")` | chiffre le pointeur du partage |
| `sig_priv_share` | graine `KDF(priv_user, "share-signing", —, share_id)` | signe l'entrée de l'annuaire ; **propriétaire seul** |
| clé de l'annuaire | `SHA-256(sig_pub_share ‖ "share")` | recherche de l'entrée |

Le **jeton de partage** transmis au destinataire est `S ‖ sig_pub_share`
(64 o). `S` permet de lire, `sig_pub_share` de vérifier que l'entrée vient
du propriétaire : un destinataire ne peut pas réécrire le pointeur.

## Pointeur vivant dans l'annuaire {: #pointeur }

Entrée [`network.ShareEntry`](../02-schemas/network/ShareEntry.md)
([`network.dht-directory`](../01-network-dht/dht-directory.md#champs-publies)),
signée par `sig_priv_share`, `seq` strictement croissant. Son contenu
chiffré, `SharePointer`, donne la version courante : `first_block_hash`,
`element_key` (la `K_elem` de cette version), nom, taille, Nœud du
propriétaire et ses adresses, autorisation de lecture. Le Connecteur du
propriétaire le republie **à chaque synchronisation qui change
l'élément** (nouvelle version, donc nouvelle clé d'élément) et toutes les
2 592 000 s ; TTL 15 552 000 s. Un élément renommé ou déplacé reste suivi
tant que le Connecteur le retrouve ; supprimé, le partage passe à
`revoked`.

## Lecture chez le Nœud du propriétaire {: #lecture }

Le propriétaire signe une **autorisation de partage** (`SignedShareGrant`
de [`protocols.echange-blocs`](echange-blocs.md)) : son `user_id`, le Nœud
qui la sert, `share_id`, expiration facultative. N'importe quel Connecteur
la présente (`ShareCredential`) pour lire par `GetBlock` les blocs de ce
propriétaire. Le Nœud vérifie la signature par `pub_user` d'un de ses
Utilisateurs, l'expiration et la liste des partages retirés, puis sert
avec un débit limité (1 000 blocs par minute et par partage). Il ne voit
que du chiffré : il ne sait ni ce qui est partagé ni avec qui.

## Destinataire {: #destinataire }

- **Utilisateur S3m** : le propriétaire désigne le destinataire par son
  identifiant (`user_id`, dont il vérifie l'empreinte). L'invitation
  `S3MS1:<base64url>` chiffre le jeton pour lui seul : clé éphémère
  X25519, `KDF(X25519(éph, pub_user_x25519 du destinataire), "share-invite",
  —, pub éphémère)`, AEAD (conversion Ed25519 → X25519 de
  [`crypto.k-attach`](../03-crypto/k-attach.md)). Le propriétaire la
  transmet par le moyen de son choix (courriel, messagerie) ; seul le
  destinataire peut l'ouvrir.
- **Lien S3m** : `s3m://partage#<base64url(jeton)>`. Le jeton est après le
  `#` : il n'est jamais envoyé à un serveur. Qui détient le lien lit ; il
  s'ouvre dans n'importe quelle installation de S3m, même sans compte.

## Côté Connecteur {: #connecteur }

- **Page « Partages »** du tableau de bord
  ([`deploiement.packaging`](../07-deploiement/packaging.md)) : explorateur
  de ses fichiers, choix d'un fichier ou d'un dossier, d'un destinataire
  ou d'un lien, d'une expiration ; liste des partages donnés (retrait) et
  reçus (ajout d'une invitation ou d'un lien, retrait de la liste).
- **Partages reçus** affichés dans le lecteur ou le dossier synchronisé
  ([`protocols.acces-applicatif`](acces-applicatif.md)), en lecture seule :
  `Partagés avec moi\<pseudo du propriétaire> — <nom>`. Les blocs sont
  lus chez le Nœud du propriétaire et vérifiés comme les siens
  ([`protocols.integrite-lecture`](integrite-lecture.md)).

## Retrait {: #retrait }

Le propriétaire retire un partage : son Connecteur envoie `RevokeShare` à
son Nœud, qui refuse désormais l'autorisation, et publie un pointeur
`revoked`. **Ce qu'un destinataire a déjà téléchargé ne peut pas lui être
repris** : c'est la limite de tout partage chiffré. Pour couper aussi
l'accès aux versions suivantes, le partage est retiré, pas seulement mis à
jour.

## Limites {: #limites }

- Le partage est en lecture seule. L'écriture partagée viendra à l'étape
  suivante.
- Le destinataire voit la taille, le nom et l'arborescence de l'élément
  partagé, pas le reste de l'espace du propriétaire.
- Le Nœud du propriétaire doit être joignable par le destinataire : un
  Nœud joignable seulement sur le réseau local ne sert que ce réseau.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
