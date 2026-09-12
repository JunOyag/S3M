---
id: emergency.EmergencyBlockEntry
kind: schema
title: "EmergencyBlockEntry"
section: "§3.12.4"
fbs_source: "schemas/emergency/EmergencyManifest.fbs#EmergencyBlockEntry"
status: draft
verified_by: []
---

# EmergencyBlockEntry

Un bloc de données brut déposé en urgence chez un
[`emergency.EmergencyPartner`](EmergencyPartner.md) — **aucune parité à ce
stade**, contrairement au troc normal.

## Champs

```
--8<-- "emergency/EmergencyBlockEntry.table.md"
```

`block_hash` référence un bloc chiffré sous
[`crypto.k-block`](../../03-crypto/k-block.md), exactement comme en
fonctionnement normal — seule la stratégie de dispersion diffère (répartition
à parts égales entre `n_secours` partenaires, sans calcul Reed-Solomon). Voir
[`protocols.espace-secours`](../../04-protocols/espace-secours.md) pour la
mécanique complète et [`protocols.erasure-coding`](../../04-protocols/erasure-coding.md)
pour la comparaison avec la dispersion normale.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
