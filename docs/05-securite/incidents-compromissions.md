---
id: securite.incidents-compromissions
kind: narrative
title: "Gestion des Incidents & Compromissions"
section: "§5.2"
status: draft
verified_by: []
---

# Gestion des Incidents & Compromissions

- **Absence/Échec PoS (timeout)** : purge après 6 mois hors-ligne — voir
  [`protocols.volatilite-reparation`](../04-protocols/volatilite-reparation.md).
- **Compromission clé User** : nouvelle identité User (index suivant si seule
  une clé dérivée a fuité, nouvelle phrase mnémonique si la seed elle-même
  a fuité — règle complète sur
  [`crypto.identity-derivation`](../03-crypto/identity-derivation.md)),
  re-wrap de la chaîne de clés maîtresses ([`crypto.master-key-chain`](../03-crypto/master-key-chain.md))
  et réémission de l'entrée DHT. Les blocs existants ne sont **pas**
  rechiffrés.

## Compromission Clé Node

Contrairement au User, ce cas implique **tous les Utilisateurs rattachés** —
`K_attach` dépendant de `pub_node` pour chacun, changer d'identité Node
invalide leur attachement simultanément, nécessitant une réattache complète.

### Mécanisme — clé de secours et pointeur de migration

1. **Clé de secours pré-provisionnée** : dès sa création, le Nœud dérive
   `priv_node_recovery`/`pub_node_recovery` sur le chemin dédié
   `m/0x703270'/2'/<index>'` — en miroir de l'identité `…/1'/<index>'` de la
   même seed (schéma complet :
   [`crypto.identity-derivation`](../03-crypto/identity-derivation.md)) —
   « un chemin de dérivation distinct » au sens du §5.2.
   `pub_node_recovery` est publiée dès l'origine, en clair, dans
   l'entrée DHT Node ([`network.dht-directory`](../01-network-dht/dht-directory.md))
   — un champ immuable.
2. **Publication du pointeur.** En cas de compromission de `priv_node`
   (mais pas de la seed), l'opérateur signe avec `priv_node_recovery` une
   [`network.SignedMigrationPointer`](../02-schemas/network/SignedMigrationPointer.md)
   portant `{old_node_id, new_node_id, seq, timestamp}` et la publie dans
   le champ `migration_pointer` de l'entrée DHT **de l'ancien** `node_id`.
    - **Signature** : Ed25519 par `priv_node_recovery` sur
      `L("s3m/sig/migration-pointer/v1") ‖ payload` — règle de
      séparation de contexte commune à toutes les signatures DHT
      ([`network.dht-directory`](../01-network-dht/dht-directory.md)).
    - **Vérification** : par tout pair, via le `pub_node_recovery` déjà
      publié dans l'entrée Node, sans dépendre de la clé compromise.
      `old_node_id` doit être celui de l'entrée qui porte le pointeur.
    - **Séquence et rejeu** : `seq` est monotone (premier pointeur : 1).
      Les pairs rejettent un pointeur dont `seq` est inférieur ou égal à
      celui déjà publié, ce qui empêche le rejeu d'un ancien pointeur et
      départage deux pointeurs concurrents.
3. **Côté Connecteur.** Lors de la résolution périodique de son Nœud (ou
   dès l'échec d'une opération), le Connecteur vérifie la présence d'un
   `migration_pointer` valide sur l'entrée de son `node_id` connu. Avant de
   le suivre, il vérifie que **l'entrée Node de `new_node_id` existe et est
   valide** (preuve VDF et signature vérifiées) : un pointeur vers une
   identité inexistante ou non vérifiable est ignoré. Le suivi automatique
   se limite à **un seul saut** : si l'entrée de `new_node_id` porte
   elle-même un `migration_pointer`, le Connecteur ne le suit pas et
   demande une confirmation explicite à l'utilisateur. Un suivi valide
   déclenche la réattache, selon le même flux que
   [`protocols.migration-noeud`](../04-protocols/migration-noeud.md).
4. **Continuité réseau** : si la même machine/IP/port est conservée, le
   nouveau Nœud peut être joignable à la même adresse sous sa nouvelle
   identité.

### Limite fondamentale {: #limite-fondamentale }

Si c'est la **seed elle-même** qui est exfiltrée, `priv_node_recovery` est
également compromise — aucun mécanisme cryptographique ne peut garantir
l'authenticité d'un pointeur de migration. L'avertissement des
Utilisateurs passe alors par l'alerte signée par la clé d'annonce, extérieure
à la seed et épinglée par chaque Connecteur
([`protocols.canal-noeud`](../04-protocols/canal-noeud.md)) ; si cette clé a
fuité elle aussi, seule une communication hors du protocole reste possible. La limite
d'un seul saut automatique réduit toutefois l'impact d'une redirection en
chaîne par un attaquant qui aurait obtenu la seed.

### Variante — perte sans compromission (panne matérielle) {: #variante-perte-sans-compromission }

Même mécanisme lorsque l'opérateur a perdu l'accès opérationnel (disque
détruit) tout en conservant la seed. Il dérive un nouveau `node_id` à
l'index suivant `…/1'/<index+1>'` — avec sa clé de secours miroir
`…/2'/<index+1>'` (voir
[`crypto.identity-derivation`](../03-crypto/identity-derivation.md)) — depuis
cette même seed et suit
[`protocols.migration-noeud`](../04-protocols/migration-noeud.md), avec deux
différences :

- **Conservation des partenaires d'origine** : redispersion vers les
  **mêmes partenaires**, soldes
  [`node.PartnerAccount`](../02-schemas/node/PartnerAccount.md) transférés
  tels quels.
- **Continuité d'écriture** : les Connecteurs peuvent utiliser
  [`protocols.espace-secours`](../04-protocols/espace-secours.md) pendant
  toute la fenêtre de transition (partenaires joignables par définition),
  avec repli sur la [`protocols.write-queue`](../04-protocols/write-queue.md)
  si le réseau venait lui aussi à manquer.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
