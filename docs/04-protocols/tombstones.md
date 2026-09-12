---
id: protocols.tombstones
kind: narrative
title: "Suppression Bilatérale (Tombstones 1:1)"
section: "§4.3"
status: draft
verified_by: []
---

# Suppression Bilatérale (Tombstones 1:1)

- Signalement de suppression avec preuve d'identité et timestamp lors de la
  suppression d'un fichier.
- **Libération bilatérale équivalente** des blocs partenaires, pour
  préserver le solde de [`node.PartnerAccount`](../02-schemas/node/PartnerAccount.md).

Déclenché notamment par :

- la purge différée qui suit une dispersion (copy-on-write), voir
  [`protocols.dispersion-transactionnelle`](dispersion-transactionnelle.md) ;
- la réémission intégrale d'un fichier modifié, voir
  [`protocols.fs-structure`](fs-structure.md#immuabilite) ;
- le remplacement a posteriori d'un stripe avec padding, voir
  [`protocols.erasure-coding`](erasure-coding.md#assemblage-progressif) ;
- la réconciliation confirmée d'un
  [`emergency.EmergencyManifest`](../02-schemas/emergency/EmergencyManifest.md),
  voir [`protocols.espace-secours`](espace-secours.md).

Côté disque, une suppression confirmée se traduit par la libération du slot
correspondant dans son [`node.ContainerFile`](../02-schemas/node/ContainerFile.md)
(bit de bitmap remis à zéro, espace récupéré immédiatement via
hole-punching) — voir
[`protocols.stockage-physique`](stockage-physique.md#suppression-dun-bloc)
pour le mécanisme physique complet.

À la différence de la rupture pour fraude
([`securite.blacklist-fraude`](../05-securite/blacklist-fraude.md)), cette
procédure est **notifiée** au partenaire — c'est une suppression légitime,
pas une sanction.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
