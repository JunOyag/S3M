---
id: deploiement.contacts
kind: narrative
title: "Contacts Synchronisés"
section: "§3.11"
status: draft
verified_by: []
---

# Contacts Synchronisés

Fonctionnalité ajoutée le 2026-11-23. Les contacts du Connecteur (page
« Contacts », [`deploiement.packaging`](packaging.md#contacts)) sont les
mêmes sur tous les appareils d'une identité, et reviennent avec elle lors
d'une restauration depuis la phrase de récupération
([`crypto.k-self`](../03-crypto/k-self.md)).

## Stockage {: #stockage }

Les contacts sont publiés dans l'entrée User, champ `contacts` de
[`network.UserEntryPlaintext`](../02-schemas/network/UserEntryPlaintext.md),
une entrée [`network.ContactRecord`](../02-schemas/network/ContactRecord.md)
par contact. Ils sont donc chiffrés sous `K_self`, comme le pseudo de
l'identité ([`deploiement.pseudos`](pseudos.md#noms)) : ni le Nœud, ni les
hébergeurs de l'annuaire, ni les contacts eux-mêmes ne les lisent. Aucune
nouvelle clé, aucun nouveau type d'entrée.

Le Connecteur garde une copie locale (`contacts.json`, données de
l'identité) : la page Contacts et les partages
([`protocols.partage`](../04-protocols/partage.md)) restent utilisables
hors ligne ; les changements sont publiés dès que l'annuaire est
joignable.

## Fusion entre appareils {: #fusion }

L'entrée User est unique et la plus récente l'emporte
([`network.dht-directory`](../01-network-dht/dht-directory.md#regles-de-verification-a-la-lecture)) :
la fusion se fait donc contact par contact, avant chaque publication et à
chaque lecture.

- Pour un même `user_id`, la version au `updated_at` le plus grand gagne ;
  à égalité, une suppression l'emporte, puis le plus petit pseudo en ordre
  d'octets (choix déterministe, identique sur tous les appareils).
- Supprimer un contact le garde comme **marque** (`deleted = true`, pseudo
  vide, `updated_at` de la suppression) : sans elle, un autre appareil le
  réintroduirait. Une marque de plus de 90 jours est retirée.
- Deux contacts ne peuvent porter le même pseudo (sans casse) : après
  fusion, le plus récent garde le pseudo, l'autre est vidé (contact gardé,
  sans pseudo).
- Modifier l'identifiant d'un contact = supprimer l'ancien (marque) et
  créer le nouveau.

## Publication et lecture {: #publication }

- Toute modification (ajout, édition, suppression, import) déclenche une
  réémission de l'entrée User, regroupée sur 30 s : une rafale de
  modifications ne publie qu'une fois.
- L'entrée est relue au démarrage puis toutes les 10 minutes ; une entrée
  plus récente que la dernière lue est fusionnée avec la copie locale, qui
  est publiée à son tour si la fusion l'a modifiée.
- Une réémission pour une autre raison (racine des fichiers, pseudo) porte
  toujours la liste fusionnée courante.

## Taille {: #taille }

- **200 contacts au plus**, marques comprises ; au-delà, l'ajout est
  refusé (les marques les plus anciennes sont purgées d'abord).
- **Complément** : le clair est complété par le champ `padding` (zéros)
  jusqu'au multiple de 4 096 o supérieur, pour que la taille publiée ne
  révèle pas le nombre de contacts à 4 Kio près.
- Un message de l'annuaire (enregistrement compris) peut atteindre
  **64 Kio** ([`network.dht-directory`](../01-network-dht/dht-directory.md#tailles)) :
  200 contacts (environ 24 Kio) tiennent avec le reste de l'entrée User.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
