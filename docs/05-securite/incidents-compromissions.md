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
2. En cas de compromission de `priv_node` (mais pas la seed), l'opérateur
   signe avec `priv_node_recovery` un `migration_pointer`
   `{old_node_id, new_node_id, timestamp}`, vérifiable par tout pair DHT via
   `pub_node_recovery`.
3. Le Connecteur vérifie périodiquement la présence d'un `migration_pointer`
   valide ; s'il en trouve un, il déclenche automatiquement une réattache —
   même flux que [`protocols.migration-noeud`](../04-protocols/migration-noeud.md),
   initié par le pointeur plutôt qu'un choix explicite.
4. **Continuité réseau** : si la même machine/IP/port est conservée, le
   nouveau Nœud peut être joignable à la même adresse sous sa nouvelle
   identité.

### Limite fondamentale {: #limite-fondamentale }

Si c'est la **seed elle-même** qui est exfiltrée, `priv_node_recovery` est
également compromise — aucun mécanisme cryptographique ne peut garantir
l'authenticité d'un pointeur de migration. Nécessite une communication
hors-bande, hors du périmètre cryptographique de ce protocole.

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
