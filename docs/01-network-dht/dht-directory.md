---
id: network.dht-directory
kind: narrative
title: "Annuaire DHT & Entrées Publiées"
section: "§2.1, §3.9"
status: draft
verified_by: []
---

# Annuaire DHT & Entrées Publiées

La DHT Kademlia agit uniquement comme un annuaire public indexé par
l'Identité unique. Elle ne stocke **aucun identifiant de bloc individuel**
ni la cartographie des stripes.

## Clés de recherche

- **Node** : indexé directement par la clé publique du Node (découverte
  publique nécessaire à l'appairage).
- **User** : indexé par `user_dht_key = KDF(priv_user, pub_user,
  "dht-lookup")` — jamais par la clé publique brute. Connaître `pub_user`
  ne suffit donc pas à localiser l'entrée ; seul le User (via sa clé
  privée) peut la calculer.
- **DispersalManifest** : `dht_key = H(K_attach)` — voir
  [`crypto.k-attach`](../03-crypto/k-attach.md).
- **EmergencyManifest** : `emergency_dht_key = H(K_attach || "emergency")`
  — voir [`protocols.espace-secours`](../04-protocols/espace-secours.md).

## Signature sans exposer les identités

Le Connecteur dérive une paire de signature dédiée au slot,
`sig_priv_user = KDF(priv_user, pub_user, "dht-signing")`, publiée
auto-certifiante dans l'entrée elle-même (même principe qu'IPNS). Pour le
DispersalManifest, `sig_priv_dispersal = KDF(K_attach, "dispersal-signing")`
— voir [`crypto.k-attach`](../03-crypto/k-attach.md#portee-de-signature-derivee)
pour le détail de cette dérivation et son asymétrie d'usage.

## Champs publiés par type d'entrée {: #champs-publies }

| Identité | Champs publiés | Durée de vie |
|---|---|---|
| **Node** | IP/port, preuve d'identité, `pub_node_recovery`, `migration_pointer` optionnel, `Encrypt(K_node_self, {node_snapshot_root_hash, node_snapshot_root_partners})` | 6 mois, republication mensuelle |
| **User** | preuve d'identité, `Encrypt(K_self, {fs_root_hash, encryption_salt, key_version, attachments[…], master_key_chain[…]})`. **Pas d'IP/port** : le Connecteur n'accepte aucune connexion entrante | 10 ans |
| **DispersalManifest** | `sig_pub_dispersal` en clair, `Encrypt(K_attach, {dispersal_root_hash, dispersal_root_partners})` | 6 mois, republication mensuelle |
| **EmergencyManifest** | `Encrypt(K_emergency_content, {partners, blocks, mutations, base_fs_root_hash})`, signée `sig_priv_emergency` | 6 mois, **sans** republication |

## Rôle de `dispersal_root_partners`

Ce champ n'est pas redondant avec la table
[`dispersal.Partner`](../02-schemas/dispersal/Partner.md) : il résout un
problème d'amorçage. La table `Partner` complète n'est disponible qu'**à
l'intérieur** du contenu chiffré du bloc racine lui-même — pour récupérer ce
tout premier bloc via erasure coding, il faut donc déjà savoir *qui* héberge
ses fragments de parité. D'où la nécessité de publier, en clair dans
l'entrée DHT, les partenaires du **stripe racine spécifiquement**.

## Expiration & republication — trois régimes {: #expiration-et-republication }

- **Node et DispersalManifest** (6 mois) : republication mensuelle
  obligatoire, même sans changement de contenu, lissée sur le mois (hash de
  `user_id`) pour éviter un pic de charge périodique.
- **EmergencyManifest** (6 mois, **jamais republiée**) : structure
  temporaire par nature — écrite une fois, supprimée dès réconciliation.
- **User** (10 ans) : réactif (republication immédiate à chaque écriture
  confirmée) ou fallback (après 1 an d'inactivité) — voir
  [`network.bootstrap`](bootstrap.md) pour l'usage de la comparaison de
  timestamp au chemin rapide.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
