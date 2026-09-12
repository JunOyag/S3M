---
id: protocols.quota-sync
kind: narrative
title: "Gestion du Quota à la Synchronisation"
section: "§3.12.3"
status: draft
verified_by: []
---

# Gestion du Quota à la Synchronisation (Multi-Connecteurs)

Le Connecteur connaît son [`node.UserQuota`](../02-schemas/node/UserQuota.md)
et le nombre de blocs libres restants au moment où il passe hors-ligne. Mais
si **plusieurs Connecteurs du même Utilisateur** écrivent hors-ligne en
parallèle, chacun en respectant le quota connu **de son point de vue**, leur
somme peut dépasser le quota réel une fois les deux files rejouées.

## Résolution

- **Côté Nœud** : à la synchronisation, intégration des mutations reçues de
  tous les Connecteurs de l'Utilisateur **par timestamp croissant**, tous
  appareils confondus, jusqu'à saturation du quota.
- **Rejet** : les entrées de [`fs.WriteQueue`](../02-schemas/fs/WriteQueue.md)
  reçues après saturation sont **rejetées** et renvoyées (liste des
  `block_hash`) à leur Connecteur d'origine.
- **Côté Connecteur** : mapping de la liste rejetée vers les fragments de
  fichiers concernés (un fichier peut être partiellement accepté si sa
  chaîne est coupée), puis proposition à l'utilisateur (libérer de
  l'espace, supprimer d'autres fichiers, ou conserver en attente).

Cette même logique de rejet par timestamp croissant s'applique à l'espace de
secours — voir
[`protocols.espace-secours`](espace-secours.md#integration-physique-au-retour-du-noeud).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
