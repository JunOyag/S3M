---
id: emergency.EmergencyPartner
kind: schema
title: "EmergencyPartner"
section: "§3.12.4"
fbs_source: "schemas/emergency/EmergencyManifest.fbs#EmergencyPartner"
status: draft
verified_by: []
---

# EmergencyPartner

Partenaire de proximité sollicité pour un dépôt d'urgence — sélectionné par
distance XOR de l'**identité du Connecteur/Utilisateur**, pas du Nœud (voir
[`protocols.espace-secours`](../../04-protocols/espace-secours.md#selection-des-partenaires-de-secours)).

## Champs

```
--8<-- "emergency/EmergencyPartner.table.md"
```

Structurellement distinct de
[`dispersal.Partner`](../dispersal/Partner.md) : ces partenaires ne sont
pas nécessairement les mêmes que ceux du troc normal, et n'ont a priori
aucune relation `PartnerAccount` préexistante avec le Nœud d'origine.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
