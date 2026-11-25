---
id: protocols.historique-versions
kind: narrative
title: "Historique des Versions et Retour Arrière"
section: "§5.2"
status: draft
verified_by: []
---

# Historique des Versions et Retour Arrière

Ajout du 2026-11-25. Protège contre un rançongiciel ou une suppression
accidentelle chez l'Utilisateur : les versions passées de son espace restent
lisibles et restaurables pendant une **durée de conservation** (30 jours par
défaut, réglage `history_days` du Nœud ; 0 : aucun historique), comptées dans
son quota.

## Côté Nœud

À chaque `CommitRoot` qui change la racine
([`protocols.echange-blocs`](echange-blocs.md)), la racine remplacée est
gardée avec son descripteur scellé
([`crypto.k-self#k-root`](../03-crypto/k-self.md#k-root)), sa date de
validation et sa date de remplacement ; elle est oubliée au-delà de la
conservation. Le Nœud ne voit que des hash : il ne sait pas quels blocs
appartiennent à quelle version.

| Requête (`UserCredential`) | Réponse |
|---|---|
| `ListRoots` | `RootList` : versions, la plus récente d'abord, et `retention_s` |
| `PurgeRoots { before }` | `Ack` : versions remplacées avant `before` oubliées (0 : toutes) |

L'historique est gardé dans l'état du Nœud, pas dans son snapshot.

## Côté Connecteur

- **Blocs gardés** : les blocs qu'une nouvelle racine remplace ne sont plus
  libérés aussitôt mais gardés avec leur date de remplacement, et libérés
  (`ReleaseBlocks`) après la conservation annoncée par le Nœud — sauf ceux
  encore atteints par la racine courante ou une version gardée (un même
  bloc peut revenir). La vérification a lieu au plus une fois par heure.
- **Parcours** : l'Explorateur liste les versions (bouton « Versions »,
  « Versions… » sur un fichier ou un dossier) ; une version passée se
  parcourt en lecture seule, signalée par un bandeau, et se télécharge.
- **Restauration** : un fichier ou un dossier d'une version passée est
  recopié dans l'espace courant comme une nouvelle modification ; la
  version remplacée entre à son tour dans l'historique.
- **Purge** : page Fichiers et synchronisation, « Purger celle-ci et les
  plus anciennes » ou « Purger tout l'historique » (confirmation) :
  `PurgeRoots`, puis libération des blocs gardés qui ne sont plus atteints.
  « Libérer les anciennes versions » ne touche jamais l'historique.
- **Garde-fou** : au moins 100 fichiers existants modifiés dans une même
  synchronisation suspendent l'envoi et préviennent l'Utilisateur
  (rançongiciel ?) ; sa reprise vaut accord pour cette synchronisation.

## Références

- `protocols.echange-blocs` — Protocole d'Échange de Blocs
- `crypto.k-self` — K_self — Récupération depuis la Seed
- `protocols.write-queue` — Écriture Hors-Ligne — WriteQueue
- `protocols.acces-applicatif` — Accès Applicatif — Lecteur Monté natif
