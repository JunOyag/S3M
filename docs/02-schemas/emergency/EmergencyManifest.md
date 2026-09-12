---
id: emergency.EmergencyManifest
kind: schema
title: "EmergencyManifest"
section: "§3.12.4"
fbs_source: "schemas/emergency/EmergencyManifest.fbs#EmergencyManifest"
status: draft
verified_by: []
---

# EmergencyManifest

Racine de l'espace de secours pour un utilisateur en détresse — une
instance par `user_id`, **indépendante du Nœud**.

## Champs

```
--8<-- "emergency/EmergencyManifest.table.md"
```

Référence [`emergency.EmergencyPartner`](EmergencyPartner.md),
[`emergency.EmergencyBlockEntry`](EmergencyBlockEntry.md) et
[`emergency.EmergencyMutation`](EmergencyMutation.md). Chiffrée avec
`K_emergency_content` (dérivée de
[`crypto.k-attach`](../../03-crypto/k-attach.md)), publiée en DHT sous
`emergency_dht_key = H(K_attach || "emergency")` — **jamais** le
`DispersalManifest`, conformément à la règle « seul le Nœud écrit et signe
le DispersalManifest » (voir
[`protocols.suppression-dispersal`](../../04-protocols/suppression-dispersal.md)).

Ne référence **jamais de Connecteur émetteur**, seulement le `user_id` :
n'importe quel Connecteur de cet utilisateur peut la découvrir et la
réconcilier — voir
[`protocols.espace-secours`](../../04-protocols/espace-secours.md) pour le
protocole complet (dispersion, intégration au retour du Nœud, boucle de
surveillance, dimensionnement `E_secours`).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
