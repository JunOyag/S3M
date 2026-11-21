---
id: protocols.partenariat-automatique
kind: narrative
title: "Partenariats et Rattachements Automatiques"
section: "§3.3"
status: draft
verified_by: []
---

# Partenariats et Rattachements Automatiques

Fonctionnalité ajoutée le 2026-11-20. Le Nœud trouve et évalue lui-même ses
partenaires de troc 1:1 ([`node.PartnerAccount`](../02-schemas/node/PartnerAccount.md))
et accepte le rattachement automatique d'Utilisateurs
([`node.AttachedUser`](../02-schemas/node/AttachedUser.md)) selon une
politique réglable. Messages : [`protocols.echange-blocs`](echange-blocs.md).

```
--8<-- "network/Probe.table.md"
```
```
--8<-- "network/ProposePartnership.table.md"
```
```
--8<-- "network/Attach.table.md"
```

## Découverte

Toutes les 10 minutes, le Nœud parcourt la DHT
([`network.dht-directory`](../01-network-dht/dht-directory.md)) vers une clé
aléatoire et retient les pairs serveurs rencontrés. Un pair ne devient
**candidat** que si son entrée Node est valide — preuve VDF comprise
([`network.vdf-identity`](../01-network-dht/vdf-identity.md)) — et s'il
n'est pas en liste noire ([`securite.blacklist-fraude`](../05-securite/blacklist-fraude.md)).
Seuls les Nœuds publiant une adresse joignable sont trouvés (traversée de
NAT hors périmètre).

## Score

Chaque candidat et partenaire reçoit un `Probe` toutes les 5 minutes
(réponse `ProbeReply`). Le score, entre 0 et 1, combine :

| Composante | Mesure | Poids par défaut |
|---|---|---|
| Fiabilité `R` | challenges PoS réussis ([`securite.pos-challenges`](../05-securite/pos-challenges.md)) : `(réussis + 1) / (total + 2)`, 0,5 sans historique | 0,5 |
| Disponibilité `A` | moyenne glissante (α = 1/16) des `Probe` ayant répondu | 0,3 |
| Vitesse `V` | `min(1, 200 ms / latence moyenne)` | 0,2 |

`S = 0,5·R + 0,3·A + 0,2·V`. Poids et seuils sont réglables.

## Établissement d'un partenariat

Tant que le Nœud compte moins de partenaires actifs que la cible (coef×k
+ 4 par défaut, coef×k au moins), il propose un partenariat (`ProposePartnership`) aux
candidats de meilleur score, au-dessus du seuil de placement, qui
acceptent des propositions. La proposition porte l'entrée DHT Node signée
du demandeur, que le destinataire vérifie lui-même (preuve VDF comprise).
Le destinataire accepte automatiquement si sa politique le permet (nombre
maximal de partenaires, demandeur hors liste noire) et répond
`PartnershipAnswer` : 0 = refus, toute autre valeur = accepté. Depuis le
2026-11-21, aucun solde n'est négocié : `allowance_blocks` et
`granted_blocks` valent 1 et ne bornent rien, l'échange suivant la règle
d'équilibre de [`node.PartnerAccount`](../02-schemas/node/PartnerAccount.md#equilibre).

**Partenaires manquants** : si un stripe ne trouve pas coef×k partenaires
distincts qui acceptent l'échange, le Nœud relève sa cible du nombre
manquant et propose de nouveaux partenariats ; la cible revient à sa valeur
réglée quand les stripes sont placés.

## Placement et retrait

- Seuls les partenaires dont le score atteint le **seuil de placement**
  (0,5 par défaut) reçoivent de nouveaux fragments ; parmi eux, l'ordre reste
  la distance XOR ([`protocols.dispersion-transactionnelle`](dispersion-transactionnelle.md#orchestration)).
- Un partenaire sous le **seuil de retrait** (0,35) pendant 7 jours est
  **en retrait** : ses fragments sont replacés ailleurs comme pour une
  absence ([`protocols.volatilite-reparation`](volatilite-reparation.md)),
  puis le partenariat prend fin une fois les anciens fragments purgés par
  tombstones. La fraude reste traitée immédiatement par la liste noire.

## Rattachement automatique des Utilisateurs

Le Connecteur d'un Utilisateur non rattaché envoie `Attach` à son Nœud :

- identifiant `UserCredential` calculé avec le `K_attach` du sel proposé
  ([`crypto.k-attach`](../03-crypto/k-attach.md)) — preuve de possession
  de `priv_user`, sans nouvelle clé ;
- preuve VDF de `0x00 ‖ sig_pub_user` et signature de `sig_priv_user` sur
  `L("s3m/sig/attach/v1") ‖ pub_user ‖ node_id`. Une identité VDF
  ne sert qu'à un seul rattachement automatique (anti-Sybil).

Politique du Nœud, réglable dans son dashboard
([`deploiement.packaging`](../07-deploiement/packaging.md)) : activation,
quota attribué, nombre maximal d'Utilisateurs rattachés automatiquement,
budget total. Réponse `Attached` (quota attribué) ou `Failure`
(`Unauthorized`, `QuotaExceeded`). Le quota de chaque Utilisateur reste
modifiable à la main.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
