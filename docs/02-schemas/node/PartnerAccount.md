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

Solde du troc 1:1 avec un partenaire.

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

## Règle d'équilibre {: #equilibre }

Ajout du 2026-11-21 : le troc est strictement 1 pour 1, **sans solde
négocié** (`allowance_blocks` est ignoré). Un Nœud accepte un fragment de
parité d'un partenaire P (`StoreFragment`) seulement si, après ce dépôt,

`blocks_hosted_by_partner ≤ blocks_hosted_for_partner + 1`

sinon il répond `QuotaExceeded`. Les deux Nœuds déposent donc en
alternance, l'écart ne dépasse jamais un fragment, et un partenaire qui n'a
rien à placer ne reçoit rien de plus : l'expéditeur passe au partenaire
suivant ([`protocols.dispersion-transactionnelle`](../../04-protocols/dispersion-transactionnelle.md#orchestration)).
Un Nœud sans Utilisateurs n'héberge donc rien. Seul l'espace disque peut
encore faire refuser un dépôt conforme.

Une suppression retire des fragments d'un seul côté : l'écart qui en
résulte est toléré, et seuls les dépôts suivants, soumis à la même règle,
le résorbent ; aucun fragment n'est détruit pour rétablir l'équilibre.
Un fragment déjà hébergé (même hash) n'est pas recompté.

Libéré bilatéralement lors d'une suppression légitime — voir
[`protocols.tombstones`](../../04-protocols/tombstones.md).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
