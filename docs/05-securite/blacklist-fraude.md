---
id: securite.blacklist-fraude
kind: narrative
title: "Rupture de Confiance & Liste Noire"
section: "§5.3"
status: draft
verified_by: []
---

# Rupture de Confiance & Liste Noire (Blacklist)

## Distinction timeout vs fraude cryptographique

- **Absence de réponse (timeout)** : parcours existant — voir
  [`protocols.volatilite-reparation`](../04-protocols/volatilite-reparation.md).
- **Réponse PoS incorrecte** (hash renvoyé ≠ attendu) : preuve de fraude ou
  corruption avérée → rupture immédiate, indépendamment du parcours de
  volatilité. Voir
  [`securite.pos-challenges`](pos-challenges.md#toute-demande-de-bloc-complet-vaut-challenge-pos)
  pour l'équivalence entre challenge PoS et demande de bloc complet.

## Rupture bilatérale immédiate

Toute réponse PoS incorrecte de la part du partenaire P entraîne la
**destruction locale de l'intégralité des données hébergées pour P**, sur
toutes les relations de troc actives (rupture globale au niveau du
[`node.PartnerAccount`](../02-schemas/node/PartnerAccount.md)
Nœud↔P — non limitée à un seul stripe ni un utilisateur). Aucune
notification ni tombstone n'est adressé à P (contrairement à
[`protocols.tombstones`](../04-protocols/tombstones.md)).

**Réciprocité différée** : au prochain challenge PoS que P adressera au
nœud, celui-ci échouera mécaniquement, déclenchant à son tour la rupture
côté P — séparation bilatérale sans échange de message explicite.

Physiquement, cette destruction est rapide précisément parce que les blocs
hébergés pour un partenaire donné sont **segmentés dans leurs propres
fichiers de conteneur** — voir
[`protocols.stockage-physique`](../04-protocols/stockage-physique.md#suppression-en-masse)
pour le détail : supprimer P revient à effacer ses conteneurs en bloc, pas à
scanner un stockage partagé bloc par bloc.

## Réparation proactive

Le nœud déclenche **immédiatement** (sans attendre le cycle quotidien) la
reconstruction et redistribution vers de nouveaux partenaires de l'ensemble
des fragments confiés à P — protocole transactionnel standard, voir
[`protocols.dispersion-transactionnelle`](../04-protocols/dispersion-transactionnelle.md).

## Persistance de la liste noire

P est inscrit **de façon permanente** dans
[`node.BlacklistedPartner`](../02-schemas/node/BlacklistedPartner.md), local
au nœud, sans partage ni diffusion réseau. Survit à une restauration
complète via la seed ([`deploiement.disaster-recovery`](../07-deploiement/disaster-recovery.md)).

## Note de conception

La liste noire étant locale et indexée par l'Identité, un partenaire
malveillant pourrait régénérer une nouvelle identité. Le coût
**physiquement séquentiel** de la VDF requise (~1 min incompressible, voir
[`network.vdf-identity`](../01-network-dht/vdf-identity.md)) empêche la
génération en parallèle, mais n'empêche pas, en théorie, une régénération
après ce délai. Ce coût est jugé suffisamment dissuasif dans cette version
de la spec.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
