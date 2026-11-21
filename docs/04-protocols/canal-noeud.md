---
id: protocols.canal-noeud
kind: narrative
title: "Canal Nœud ↔ Utilisateurs"
section: "§5.2"
status: draft
verified_by: []
---

# Canal Nœud ↔ Utilisateurs

Fonctionnalité ajoutée le 2026-11-21. L'opérateur d'un Nœud écrit à ses
Utilisateurs, et chaque Utilisateur écrit à son Nœud. Le canal sert surtout
au cas que le pointeur de migration ne couvre pas : la **seed du Nœud a
fuité** ([`securite.incidents-compromissions`](../05-securite/incidents-compromissions.md#limite-fondamentale)).
L'attaquant détient alors `priv_node` et `priv_node_recovery`. Seule une clé
extérieure à la seed peut encore authentifier un avertissement.

## Clé d'annonce {: #cle-annonce }

- `priv_node_announce` (Ed25519) est tirée au hasard (32 o issus du CSPRNG du
  système), **hors seed**. Elle est remise une seule fois à l'opérateur sous
  forme d'une phrase BIP-39 de 24 mots (entropie = les 32 o), à conserver à
  part de la seed. Le Nœud ne la garde pas.
- `pub_node_announce` est publiée dans
  [`network.NodeEntry`](../02-schemas/network/NodeEntry.md). Pour un Nœud
  créé avant cette fonctionnalité, l'opérateur peut la générer plus tard ;
  elle ne protège alors que les rattachements qui suivent.
- **Épinglage** : le Connecteur retient la première `pub_node_announce`
  qu'il lit pour un `node_id`, au rattachement ou à la première lecture de
  l'entrée Node qui en porte une. Il ignore toute autre valeur publiée
  ensuite. L'épinglage est perdu au changement de Nœud et refait sur le
  nouveau.

## Messages {: #messages }

Format : [`network.SignedNodeMessage`](../02-schemas/network/SignedNodeMessage.md).

| Sorte | Signée par | Libellé de signature | Usage |
|---|---|---|---|
| `Info` | `priv_node` | `"s3m/sig/node-message/v1"` | maintenance, quota, information |
| `Alert` | `priv_node_announce` | `"s3m/sig/node-alert/v1"` | compromission, Nœud de remplacement |

Le Connecteur rejette un message dont `node_id` n'est pas son Nœud, dont
la signature ne vérifie pas (`pub_node`, ou `pub_node_announce` épinglée),
dont `text` dépasse 4 096 o, ou dont `seq` n'est pas strictement supérieur
au dernier `seq` accepté pour la même sorte. Un `successor_node_id` n'est
pris en compte que dans une `Alert`.

## Requêtes {: #requetes }

Extension de [`protocols.echange-blocs`](echange-blocs.md), Connecteur →
son Nœud, avec `UserCredential` :

| Requête | Réponse | Règle |
|---|---|---|
| `ReadMessages{since_info, since_alert}` | `Messages` | les 64 plus anciens messages de `seq` supérieur, toutes sortes confondues |
| `PostMessage{text}` | `Ack` | 4 096 o au plus ; 10 messages par Utilisateur et par 86 400 s, au-delà `RateLimited` |

Le Connecteur envoie `ReadMessages` à chaque sondage de son Nœud. Le Nœud
conserve ses messages 2 592 000 s (256 au plus, les plus anciens supprimés
d'abord) et les messages reçus des Utilisateurs (`UserMessage`) 2 592 000 s.
La confidentialité des échanges repose sur le chiffrement Noise de la
connexion : les partenaires ne les voient jamais.

## Copie dans l'annuaire {: #annuaire }

Une `Alert` est aussi publiée dans l'annuaire
([`network.AlertEntry`](../02-schemas/network/AlertEntry.md), clé
`SHA-256(pub_node_announce ‖ "alert")`, enveloppe signée par
`priv_node_announce`, libellé `"s3m/sig/alert-entry/v1"`). Durée de vie
15 552 000 s depuis `timestamp`, la même que la conservation des
fragments d'un Nœud silencieux. L'enveloppe est republiée **telle quelle**
toutes les 2 592 000 s par le Nœud et par tout Connecteur qui l'a vue :
aucune nouvelle signature n'est nécessaire. Entre deux entrées valides,
les pairs gardent celle dont l'alerte a le plus grand `seq`.

Le Connecteur lit cette entrée lorsque son Nœud est injoignable, et au
moins toutes les 86 400 s.

## Effet d'une alerte {: #effet }

- Le Connecteur affiche l'alerte en bandeau jusqu'à ce que l'utilisateur
  l'acquitte.
- Il **cesse de suivre** tout `migration_pointer` de l'ancien Nœud
  ([`securite.incidents-compromissions`](../05-securite/incidents-compromissions.md)) :
  une alerte l'emporte sur un pointeur, qu'un attaquant détenant la seed
  peut fabriquer.
- Si l'alerte porte un `successor_node_id`, il propose de se rattacher à ce
  Nœud ([`protocols.migration-noeud`](migration-noeud.md)), après vérification
  de son entrée Node. Le rattachement n'est jamais automatique : il
  demande la confirmation de l'utilisateur.
- L'alerte d'un `seq` donné n'est appliquée qu'une fois.

## Limites

- Si `priv_node_announce` et la seed fuitent ensemble, il ne reste qu'un
  contact hors du protocole.
- Un Connecteur rattaché après la fuite de la seed a pu épingler une clé
  d'annonce de l'attaquant.
- Le canal ne transporte aucun fichier : ce n'est pas une messagerie
  générale.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
