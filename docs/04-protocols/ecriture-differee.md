---
id: protocols.ecriture-differee
kind: narrative
title: "Écriture par plages et synchronisation différée"
section: "§3.12.5 (V3)"
status: draft
verified_by: []
---

# Écriture par plages et synchronisation différée

Un programme écrit dans un fichier du lecteur monté
([`protocols.acces-applicatif`](acces-applicatif.md)) **par plages
d'octets**, alors que les blocs sont immuables et chaînés par hash
([`protocols.fs-structure`](fs-structure.md#immuabilite)) : modifier un
fichier crée une nouvelle chaîne complète et supprime l'ancienne. Le
chiffrement d'une chaîne se fait du **dernier bloc vers le premier** (chaque
bloc contient le `next_hash` du suivant, voir
[`crypto.k-block`](../03-crypto/k-block.md)) : aucun bloc ne peut partir
avant que le fichier entier soit disponible en local.

## Copie locale reconstituée

À la première écriture sur un fichier existant, le Connecteur reconstitue
le fichier **en entier** dans un **espace de travail local** avant
d'accepter l'écriture. Les écritures suivantes s'appliquent à cette copie.

- La taille maximale d'un fichier modifiable est bornée par l'espace de
  travail disponible ; s'il manque, le lecteur renvoie l'erreur standard
  « disque plein » et le dashboard affiche l'occupation de l'espace de
  travail.
- L'espace de travail est un **budget indépendant** du budget `Q_max` de la
  [`protocols.write-queue`](write-queue.md#taille-limite) : il est plafonné
  par l'espace disque local libre moins une réserve réglable
  (`workspace_reserve_bytes`).
- **Durabilité locale** : la copie reconstituée est écrite sur disque et
  journalisée (même principe que la `WriteQueue`). Un plantage ou un
  redémarrage ne perd pas les modifications ; les synchronisations en
  attente reprennent au lancement.

## Délai de silence (debounce)

La synchronisation d'un fichier modifié est différée : le minuteur du
fichier redémarre à chaque écriture, et la synchronisation ne part qu'après
une période sans nouvelle écriture :

```
D = clamp( 60 s + 0,5 s × taille_du_fichier_en_MiO , 60 s , 300 s )
```

(1 MiO ≈ 1 min ; 100 MiO ≈ 1 min 50 s ; plafond de 5 min dès 480 MiO.)

- **Attente maximale** : quelle que soit l'activité, la synchronisation part
  au plus tard **15 minutes** après la première écriture non synchronisée,
  pour qu'un programme qui écrit en continu (journal, base de données) ne la
  repousse pas indéfiniment.
- **Paramétrage** : le délai minimum, le plafond de `D`, l'attente maximale
  et la réserve de l'espace de travail sont réglables dans le dashboard du
  Connecteur ([`deploiement.packaging`](../07-deploiement/packaging.md)).
  Ces réglages relèvent de la **configuration locale du Connecteur**
  (`write_back_min_delay_seconds`, `write_back_max_delay_seconds`,
  `workspace_reserve_bytes`), pas de `NodeConfig`.

## Fermeture, flush, `fsync`

Ces opérations rendent la copie locale durable mais **ne déclenchent pas**
la synchronisation. Une synchronisation immédiate n'a lieu qu'au démontage,
à l'arrêt propre du Connecteur, ou sur l'action « synchroniser maintenant »
du dashboard.

## Lecture et exposition pendant le délai

- Le lecteur sert la **version locale modifiée**, pour que l'utilisateur
  voie ses changements immédiatement.
- Tant que la synchronisation n'a pas eu lieu, la modification n'existe que
  sur le disque local (ni chez le Nœud, ni dispersée). Le délai borne cette
  fenêtre.

## Ordre d'envoi et de suppression

La nouvelle chaîne est envoyée en entier — tous les `write_block` avant
l'`update_entry`, comme pour la
[`protocols.write-queue`](write-queue.md) — chiffrée avec un
`encryption_salt` neuf. L'ancienne chaîne n'est tombstonée
([`protocols.tombstones`](tombstones.md)) qu'une fois la nouvelle
entièrement confirmée par le Nœud : jamais avant, sinon une interruption
laisserait le fichier sans version valide.

## Portée

La règle ne concerne pas les lectures ; elle s'applique de la même façon à
la création d'un fichier neuf.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
