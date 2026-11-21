---
id: deploiement.pseudos
kind: narrative
title: "Pseudos et Empreintes"
section: "§3.11"
status: draft
verified_by: []
---

# Pseudos et Empreintes

Fonctionnalité ajoutée le 2026-11-21. Elle donne aux identités des noms
lisibles, sans jamais en faire une preuve, en préalable à l'usage de
plusieurs identités dans un même Connecteur.

## Empreinte courte {: #empreinte }

`empreinte(clé) = base32(SHA-256(L("s3m/fingerprint/v1") ‖ clé))`, limitée
aux 60 premiers bits : 12 caractères de l'alphabet RFC 4648 (`A`–`Z`,
`2`–`7`), groupés par 4 (`K7F2-9QXA-M3PD`). La clé est `pub_node` pour un
Nœud et `pub_user` pour un Utilisateur. Imiter une empreinte demande de
l'ordre de 2^60 essais de clé. Pour un Nœud, chaque essai coûte en plus une
preuve VDF ([`network.dht-directory`](../01-network-dht/dht-directory.md)).

## Noms {: #noms }

| Nom | Choisi par | Rangé dans | Visible par |
|---|---|---|---|
| Nom du Nœud | l'opérateur | `name` de [`network.NodeEntry`](../02-schemas/network/NodeEntry.md) (signé, en clair) | tous |
| Pseudo de l'identité | l'Utilisateur | `pseudo` de [`network.UserEntryPlaintext`](../02-schemas/network/UserEntryPlaintext.md) (chiffré sous `K_self`) | l'Utilisateur, sur tous ses appareils |
| Nom du Nœud pour l'Utilisateur | l'Utilisateur | `node_label` de [`network.AttachmentRecord`](../02-schemas/network/AttachmentRecord.md) (même chiffrement) | l'Utilisateur, sur tous ses appareils |
| Étiquette d'un Utilisateur | l'opérateur | état local du Nœud | l'opérateur |

Le Nœud ne lit jamais le pseudo d'un Utilisateur. L'étiquette locale en
tient lieu pour l'opérateur.

## Règles {: #regles }

- Un nom fait 64 o UTF-8 au plus. Les caractères de contrôle sont retirés,
  ainsi que les espaces de début et de fin. Un nom vide équivaut à aucun
  nom. Un nom reçu trop long est tronqué à la frontière de caractère qui
  précède la limite.
- Un nom n'est ni unique ni vérifié. Aucune règle du protocole ne s'appuie
  sur lui : rattachement, partenariat, alerte et migration n'utilisent que
  les clés.
- **Affichage** : `nom · empreinte`, ou l'empreinte seule s'il n'y a pas de
  nom. Pour un Nœud, le Connecteur affiche le `node_label` de
  l'Utilisateur, à défaut le nom du Nœud. Ce nom est lu dans le champ
  `node_name` de la réponse `Messages`
  ([`protocols.canal-noeud`](../04-protocols/canal-noeud.md#requetes)) quand
  le Nœud est joignable, sinon dans le `name` de son entrée Node : il
  s'affiche ainsi même quand le Nœud ne peut pas publier son entrée. Les
  Nœuds trouvés sur le réseau local
  ([`network.bootstrap`](../01-network-dht/bootstrap.md)) s'affichent de
  même, leur nom étant lu dans le champ `node_name` de `ProbeReply`. Le Nœud affiche de même ses
  partenaires (`name` lu dans leur entrée) et ses Utilisateurs (étiquette
  locale).
- Changer son pseudo, ou le nom de son Nœud, réémet l'entrée User. Changer
  le nom du Nœud republie l'entrée Node.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
