---
id: protocols.espace-secours
kind: narrative
title: "Espace de Secours — Écriture d'Urgence"
section: "§3.12.4"
status: draft
verified_by: []
---

# Écriture d'Urgence via Partenaires de Proximité — « Espace de Secours »

Distinct de [`protocols.write-queue`](write-queue.md) (coupure réseau
**totale**), ce mécanisme s'applique quand **seul le Nœud hébergeur** est
injoignable, le Connecteur conservant un accès réseau normal. Les deux
mécanismes partagent le même budget d'écritures en attente
(`Q_max = 4 GiO`) ; seule la stratégie de dispersion diffère.

## Sélection des partenaires de secours {: #selection-des-partenaires-de-secours }

Contrairement au troc normal (distance XOR du `node_id` du Nœud), les
partenaires de secours sont sélectionnés par distance XOR de l'**identité du
Connecteur/Utilisateur** — voir
[`emergency.EmergencyPartner`](../02-schemas/emergency/EmergencyPartner.md).

## Dispersion sans erasure coding

Les blocs de données (chiffrés `K_block`) sont répartis à parts égales
entre **n_secours partenaires distincts** (4 par défaut) — charge maximale
par partenaire `Q_max / n_secours` (1 GiO par défaut).

## Pointeur de secours, jamais le DispersalManifest

```
K_emergency_content = KDF(K_attach, "emergency-content")
sig_priv_emergency  = KDF(K_attach, "emergency-signing")
```

L'[`emergency.EmergencyManifest`](../02-schemas/emergency/EmergencyManifest.md)
est publié sous `emergency_dht_key = SHA-256(K_attach ‖ "emergency")`, dans
une [`network.EmergencyEntry`](../02-schemas/network/EmergencyEntry.md)
signée avec `sig_priv_emergency` (voir
[`network.dht-directory`](../01-network-dht/dht-directory.md)). L'entrée est
**unique par `user_id`**.

### Règle de séquence — lecture, fusion, écriture {: #regle-de-sequence }

Tous les Connecteurs d'un même `user_id` partagent cette clé et cette
signature ; l'écriture suit donc une règle de séquence monotone :

1. Le Connecteur lit l'entrée courante (s'il y en a une) et note son `seq`.
2. Il **fusionne** les blocs, partenaires et mutations déjà présents avec
   les siens, sans en perdre aucun.
3. Il publie l'entrée fusionnée avec `seq + 1`.
4. **Les pairs DHT rejettent toute entrée dont `seq` est inférieur ou égal
   à celui qu'ils détiennent.** Si deux Connecteurs écrivent simultanément
   avec la même séquence, l'un est rejeté : il relit, fusionne et réessaie.

Cela évite à la fois l'écrasement des références aux blocs déposés par un
autre Connecteur et le rejeu d'une ancienne version validement signée.

## Intégration physique au retour du Nœud {: #integration-physique-au-retour-du-noeud }

Le Nœud recalcule `emergency_dht_key` pour chaque Utilisateur rattaché,
récupère les blocs, recalcule/disperse la parité normalement — étape
purement mécanique sur des blocs opaques, sans Connecteur. Seul traitement
réel : le respect du quota
([`node.UserQuota`](../02-schemas/node/UserQuota.md)), rejet par timestamp
croissant exactement comme [`protocols.quota-sync`](quota-sync.md).

## Découverte et réconciliation FS {: #decouverte-et-reconciliation }

Autonome côté Connecteur : n'importe quel Connecteur de l'Utilisateur peut
re-dériver `emergency_dht_key` et consulter la DHT. Vérification de
présence des blocs avant envoi des mutations FS — jamais de mutation
référençant un bloc manquant.

Une fois la réconciliation FS confirmée, les partenaires de secours
reçoivent un ordre de tombstone
([`protocols.tombstones`](tombstones.md)) libérant l'espace réservé.
**L'entrée DHT `EmergencyManifest` n'est pas supprimée** : il n'existe pas
d'opération de suppression pour cette entrée ; elle expire à l'issue de sa
durée de vie (15 552 000 s). Tout Connecteur qui la redécouvre après
réconciliation la traite de façon **idempotente** : la comparaison par
`base_fs_root_hash` ([`protocols.write-queue`](write-queue.md)) et la
vérification de présence des blocs sur le Nœud suffisent à ne rien
réappliquer à tort. (Neutraliser l'entrée réconciliée par une version vide
à `seq + 1` reste une option non retenue — point ❓4 de la V3, reporté.)

## Boucle de surveillance

5 minutes par défaut : retry vers le Nœud, et surveillance multi-Connecteurs
de `emergency_dht_key` pour estimer le quota réellement disponible et
alerter l'utilisateur à l'approche du dépassement. L'entrée étant unique par
`user_id` et fusionnée, le quota engagé par les autres Connecteurs se lit
dans cette entrée unique.

## Dimensionnement (`E_secours`)

```
E_secours = U_backup × (Q_max / n_secours)
```

Avec les valeurs par défaut (`Q_max=4 GiO`, `n_secours=4`, `U_backup=20`) :
**E_secours = 20 GiO** — ~1% pour un Nœud de 2 To.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
