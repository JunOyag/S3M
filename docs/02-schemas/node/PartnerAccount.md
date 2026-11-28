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

### Dimensionnement {: #dimensionnement }

Ajout du 2026-11-28. Chaque stripe de k = 4 blocs d'un utilisateur, gardés
sur ce Nœud, produit k × coef = 12 fragments de parité confiés aux
partenaires. L'échange étant de 1 pour 1, ce Nœud garde autant de fragments
pour eux. À l'équilibre, un Nœud consacre donc **1 / (1 + coef) de ses
volumes à ses utilisateurs (25 %) et coef / (1 + coef) à ses partenaires
(75 %)**, hors index, sauvegarde du Nœud et versions passées.

- **Pile d'espaces** : la capacité totale (volumes actifs) se partage entre
  le **quota utilisateurs total**, le **quota utilisateurs de secours**
  ([`protocols.espace-secours`](../../04-protocols/espace-secours.md) :
  utilisateurs accueillis × espace par utilisateur), le **réservé système**
  (2 % de la capacité : index, sauvegarde du Nœud, journal) et le **quota à
  disposition des partenaires** (capacité − quotas − secours − système).
  Le **ratio de sauvegarde** = quota des partenaires / (quotas +
  système) doit valoir coef (3) au moins.
- **Quotas** : la somme des quotas accordés (rattachement manuel ou
  automatique, changement de quota) ne dépasse jamais 1 / (1 + coef) de la
  capacité restante après le secours et le système. Au-delà, la demande est
  refusée avec une explication.
- **Espace offert automatique** (`partner_policy.offer_auto`, par défaut) :
  `offer_bytes` = quota à disposition des partenaires, recalculé à chaque
  cycle ; capacité inconnue : coef × max(quotas, données stockées), 10 Gio
  au moins. Désactivé, la valeur saisie s'applique telle quelle.
- **Équilibre du stockage** : section et voyant (santé du Nœud, dans les
  deux modes) qui montrent la pile et le ratio. Le voyant est rouge si le
  ratio passe sous coef.

### Réconciliation {: #reconciliation }

Ajout du 2026-11-28. Une fois par jour et par partenaire joignable, P liste
les fragments qu'il garde pour ce Nœud (`ListFragments`, réponse
`BlockList` par pages, [`network.BlockRequest`](../network/BlockRequest.md)).
Un fragment que ce Nœud ne référence plus nulle part (stripes de données
et d'index, snapshot, remplissage, fragments au rebut) est **orphelin**,
par exemple s'il date d'avant la perte du volume. S'il l'est encore au
passage suivant, au moins une heure plus tard, ce Nœud le fait effacer par
avis de suppression ([`protocols.tombstones`](../../04-protocols/tombstones.md)).
`hosted_for_partner` est alors recalé sur le compte de P, moins ce qui
vient d'être libéré.

Ce passage n'a jamais lieu pendant une restauration, ni avant la première
sauvegarde du Nœud : les données des utilisateurs pas encore restaurés
passeraient pour orphelines. Une restauration de la sauvegarde du Nœud
relance la réconciliation de chaque partenaire.

### Manquements {: #manquements }

Constitue un **manquement** de P : ne plus détenir un fragment confié
(contrôle `NotFound`). Un refus de dépôt faute de place (`QuotaExceeded`)
n'en est jamais un, depuis le 2026-11-28 : les comptes des deux Nœuds
peuvent diverger, par exemple avec des fragments orphelins après une
restauration. P est alors compté plein, et le remplissage qu'il garde est
libéré. Un manquement ramène `T_P` à sa
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
