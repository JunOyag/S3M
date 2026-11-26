---
id: node.PartnerAccount
kind: schema
title: "PartnerAccount"
section: "§3.11"
fbs_source: "schemas/node/NodeManifest.fbs#PartnerAccount"
status: draft
verified_by: []
---

# PartnerAccount

Quota et solde de l'échange avec un partenaire.

## Champs

```
--8<-- "node/PartnerAccount.table.md"
```

## Portée : Nœud↔Partenaire, agrégée sur tous les Users

Point structurant : le quota et la comptabilité d'échange sont tenus au
niveau **Nœud↔Partenaire**, agrégés sur l'ensemble des utilisateurs
hébergés — **pas** indépendamment par (Utilisateur, Nœud, Partenaire). Un
même Partenaire physique peut ainsi héberger des fragments de parité pour
plusieurs Utilisateurs différents de ce Nœud ; un seul solde
`PartnerAccount` est maintenu pour la relation.

C'est ce qui rend cohérente la portée « globale » du blacklist (voir
[`securite.blacklist-fraude`](../../05-securite/blacklist-fraude.md)) : la
rupture avec un partenaire fraudeur s'applique à l'ensemble de la relation
Nœud↔Partenaire, donc à tous les Utilisateurs concernés d'un coup — pas
fichier par fichier ni utilisateur par utilisateur.

## Règle d'équilibre : échange sur l'offre {: #equilibre }

Depuis le 2026-11-24, l'échange porte sur l'espace **promis** et non plus
sur l'espace déjà utilisé (le troc 1 pour 1 du 2026-11-21 et son crédit
d'hébergement du 2026-11-23 sont abandonnés) : deux partenaires
s'accordent un **quota égal Q** (en fragments de 64 Kio), et chacun peut
déposer jusqu'à Q fragments chez l'autre, quoi qu'il héberge lui-même.
Un Nœud accepte un fragment de parité d'un partenaire P (`StoreFragment`)
seulement si, après ce dépôt,

`blocks_hosted_by_partner ≤ Q`

sinon il répond `QuotaExceeded` ; seul l'espace disque peut encore faire
refuser un dépôt conforme. Un fragment déjà hébergé (même hash) n'est pas
recompté.

### Espace offert et quota {: #quota }

- **Espace offert** : réglage local `partner_policy.offer_bytes`
  (**10 Gio par défaut**). Le quota par partenaire que le Nœud peut
  promettre vaut `q = offer_bytes / 65 536 / max_partners` : la somme des
  promesses ne dépasse jamais l'espace offert.
- **Confiance** : le Nœud ne promet à P que `min(q, T_P)`, où `T_P` est sa
  confiance envers P ([ci-dessous](#confiance)).
- **Négociation** (`ProposePartnership.allowance_blocks` /
  `PartnershipAnswer.granted_blocks`, [`protocols.partenariat-automatique`](../../04-protocols/partenariat-automatique.md#negociation)) :
  le demandeur propose `allowance = min(q, T)` ; le destinataire accorde
  `Q = max(min(allowance, q', T'), ce qu'il stocke déjà chez le demandeur)`,
  ou 0 pour refuser. Les deux côtés retiennent ce même Q.
- **Pas de baisse sous l'usage** : un Nœud ne peut fixer Q en dessous de ce
  que lui-même stocke chez ce partenaire ; pour descendre plus bas, il
  libère d'abord ses propres fragments. Une baisse n'efface jamais rien :
  elle bloque seulement les nouveaux dépôts.

### Confiance progressive {: #confiance }

`T_P` part de `partner_policy.trust_initial_blocks` (**256 fragments, soit
16 Mio**) et double à la fin de chaque période
(`partner_policy.trust_period_s`, **7 jours**) sans manquement, si P a
réussi au moins un contrôle de stockage dans la période et — remplissage
actif — garde de ce Nœud au moins Q fragments (réels ou de remplissage). Il
plafonne à q. Une identité neuve n'obtient donc beaucoup qu'après avoir
longtemps prouvé qu'elle stocke.

### Remplissage {: #remplissage }

L'espace promis mais inutilisé est vérifié en le remplissant
(`partner_policy.filler`, actif par défaut) : tant qu'un partenaire garde
moins de Q fragments de ce Nœud, celui-ci lui dépose, au plus 16 par cycle
de 30 s, des **fragments de remplissage** de 64 Kio, pseudo-aléatoires
sous une clé dérivée de `priv_node` que lui seul connaît
(`SHA-256(clé ‖ indice ‖ j)`, j = 0…2047) : il les régénère sans les
stocker. Ils sont contrôlés comme les autres fragments
([`securite.pos-challenges`](../../05-securite/pos-challenges.md)) et, quand
un vrai fragment ne trouve plus de place (`QuotaExceeded` à Q atteint),
libérés par avis de suppression ([`protocols.tombstones`](../../04-protocols/tombstones.md))
au cycle suivant, 16 à la fois. Remplir coûte de l'espace disque réel aux
partenaires : c'est la preuve que la promesse est tenue. Un **refus de
remplissage** faute de place n'est jamais un manquement : le partenaire
peut garder du remplissage que ce Nœud ne connaît plus (restauration) ;
il est alors compté plein. Après une restauration, le remplissage déjà
déposé (état de dispersion conservé) est recompté dans `hosted_for_partner`.
Les partenaires mis en retrait à tort se réhabilitent depuis le dashboard
(« Réhabiliter les partenaires en retrait » : manquements effacés,
fragments gardés).

### Manquements {: #manquements }

Constituent un **manquement** de P : refuser (`QuotaExceeded`) un dépôt
alors que ce Nœud garde chez lui moins de Q fragments, ou ne plus détenir
un fragment confié (contrôle `NotFound`). Un manquement ramène `T_P` à sa
valeur initiale et suspend tout nouveau placement chez P jusqu'à la fin de
la période en cours ; **3 manquements dans une période** font passer P en
retrait ([`protocols.partenariat-automatique`](../../04-protocols/partenariat-automatique.md#placement-et-retrait)) :
ses fragments sont replacés, puis le partenariat prend fin. Un manquement
prouvé (reçu signé suivi d'une réponse fausse) relève de la liste noire
([`securite.blacklist-fraude`](../../05-securite/blacklist-fraude.md)). Les
manquements restent des observations locales, jamais diffusées.

Une réponse `Maintenance` (fragment perdu avec un volume,
[`securite.integrite-autoreparation#maintenance`](../../05-securite/integrite-autoreparation.md#maintenance))
n'est pas un manquement — le fragment est replacé — tant que la
maintenance déclarée dure **au plus 24 h** et qu'elle est la **seule de la
période de 7 jours** (un épisode se clôt après une heure sans réponse
`Maintenance`) ; au-delà, elle compte comme un `NotFound` (ajout du
2026-11-25).

Une suppression libère des fragments d'un seul côté ; le quota Q reste
inchangé.

Libéré bilatéralement lors d'une suppression légitime — voir
[`protocols.tombstones`](../../04-protocols/tombstones.md).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
