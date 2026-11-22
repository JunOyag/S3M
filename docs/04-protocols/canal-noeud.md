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
- **Remplacement** (ajout du 2026-11-22, phrase d'annonce perdue) :
  l'opérateur crée une nouvelle clé d'annonce, remise comme la première ;
  le Nœud la publie dans son entrée Node et envoie un `Info` portant
  `announce_replacement` (nouvelle `pub_node_announce`), signé par
  `priv_node`. Le Connecteur ne l'applique **jamais seul** : il demande à
  l'Utilisateur d'accepter, après confirmation de l'opérateur par un autre
  moyen, et garde l'ancienne clé tant qu'il n'a pas accepté (refus ou
  silence). Un voleur de la seed peut ainsi demander un remplacement, pas
  l'imposer.

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
pris en compte que dans une `Alert` ; `recipient` et `announce_replacement`
que dans un `Info`.

**Message à un seul Utilisateur** (ajout du 2026-11-22) : un `Info` qui
porte `recipient` n'est remis par `ReadMessages` qu'à cet Utilisateur ; le
Connecteur rejette un `Info` dont `recipient` n'est pas son `pub_user`. Le
destinataire étant signé, un message ne peut pas être réadressé. Les
numéros (`seq`) restent communs à tous les messages `Info` : un Utilisateur
voit des numéros manquants, ceux des messages adressés à d'autres.

## Requêtes {: #requetes }

Extension de [`protocols.echange-blocs`](echange-blocs.md), Connecteur →
son Nœud, avec `UserCredential` :

| Requête | Réponse | Règle |
|---|---|---|
| `ReadMessages{since_info, since_alert}` | `Messages` | les 64 plus anciens messages de `seq` supérieur destinés au demandeur (sans `recipient`, ou `recipient` = son `pub_user`), toutes sortes confondues ; `node_name` : nom actuel du Nœud ([`deploiement.pseudos`](../07-deploiement/pseudos.md#regles)) |
| `PostMessage{text}` | `Ack` | 4 096 o au plus ; 10 messages par Utilisateur et par 86 400 s, au-delà `RateLimited` ; quota, voir ci-dessous |

Le Connecteur envoie `ReadMessages` à chaque sondage de son Nœud et, quand
le Nœud est joignable, toutes les 30 s (ajout du 2026-11-22) ; chaque
nouveau message est signalé par une notification de la barre des tâches.

**Lu / non lu** (ajout du 2026-11-22, état local, hors protocole) : le
Nœud regroupe les messages reçus par Utilisateur (une conversation par
Utilisateur, avec ses réponses adressées) et les tient non lus jusqu'à
l'ouverture de la conversation ; le Connecteur tient chaque message du
Nœud non lu jusqu'à son ouverture, ou « Tout marquer comme lu ». Les
messages non lus sont comptés dans la vue d'ensemble et signalés à
l'ouverture du tableau de bord ; S3m les signale aussi par une
notification à son démarrage. Le Nœud
conserve ses messages 2 592 000 s (256 au plus, les plus anciens supprimés
d'abord) et les messages reçus des Utilisateurs (`UserMessage`) 2 592 000 s.
### Décompte du quota {: #quota }

Ajout du 2026-11-21. Chaque message conservé d'un Utilisateur occupe
**4 096 o** de son quota, quelle que soit sa longueur : le coût fixe ôte
l'intérêt d'une avalanche de messages courts. Un `PostMessage` qui ferait
dépasser le quota est refusé (`QuotaExceeded`), comme un `PutBlock`. Ces
4 096 o sont rendus quand le message disparaît (2 592 000 s écoulées, ou
suppression par l'opérateur). L'occupation communiquée dans `RootState`
([`protocols.echange-blocs`](echange-blocs.md)) les inclut. Les messages
du Nœud ne sont décomptés du quota de personne : ils sont adressés à tous,
et le Nœud les conserve une seule fois sur son propre espace.

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
