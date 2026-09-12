---
id: securite.pos-challenges
kind: narrative
title: "Challenges Dynamiques & QoS (PoS)"
section: "§5.1"
status: draft
verified_by: []
---

# Challenges Dynamiques & QoS

- Challenges réguliers de possession : calcul à la volée d'un hash
  dynamique (ex. `SHA-256(bloc + nonce)`).
- Timeout strict calculé selon la latence moyenne mesurée du partenaire.
- Priorité QoS : bridage de bande passante autorisé pour le transfert de
  blocs mais **interdiction stricte** de brider les messages PoS.

## Calcul du challenge (reconstruction locale) {: #calcul-du-challenge }

Le nœud calcule le hash de référence attendu **intégralement en local**, par
recalcul Reed-Solomon à la volée du fragment de parité concerné, à partir de
sa copie locale intégrale des k blocs de données
([`overview.architecture`](../00-overview/architecture.md), ratio 4x). Seuls
les partenaires sont challengés — ils n'hébergent que des blocs de parité.
Aucun appel réseau vers un tiers n'est nécessaire pour établir la valeur de
référence.

Cette copie locale est constituée de blocs déjà chiffrés sous
[`crypto.k-block`](../03-crypto/k-block.md) : le nœud opère uniquement sur
du texte chiffré.

## Toute demande de bloc complet vaut challenge PoS

Qu'il s'agisse d'un challenge classique (nonce seul) ou d'une demande de
récupération du bloc entier (reconstruction, migration), les mêmes règles
s'appliquent. Un partenaire qui répond correctement aux petits challenges
mais refuse ou renvoie un contenu incorrect lors d'une demande de bloc
complet est traité exactement comme un échec PoS — voir
[`securite.blacklist-fraude`](blacklist-fraude.md) pour la suite.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
