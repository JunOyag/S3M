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

## Déclenchement {: #declenchement }

Une synchronisation en attente échoue parce que le Nœud ne répond pas, et
il est injoignable depuis au moins une période de la
[boucle de surveillance](#boucle-de-surveillance) (5 minutes) : le
Connecteur construit la nouvelle arborescence comme pour une
synchronisation normale, dépose ses blocs chez les partenaires de secours
et publie l'`EmergencyManifest`. Ses copies locales restent la référence
jusqu'à la réconciliation : le dépôt rend les écritures visibles du Nœud
à son retour et des autres Connecteurs, et survit à la perte de
l'appareil. Une nouvelle modification après un dépôt donne lieu à un
nouveau dépôt à la période suivante.

Le changement de racine se note comme une mutation `update_entry` sur le
chemin `/`, dont l'`entry` porte la nouvelle racine (`first_block_hash`,
`encryption_salt`, `key_version`) ; `base_fs_root_hash` est la racine sur
laquelle elle a été construite.

## Dépôt chez les partenaires de secours {: #depot }

Ajouts à [`protocols.echange-blocs`](echange-blocs.md) du 2026-11-21.
Les partenaires candidats sont les Nœuds de la DHT, joints à l'adresse de
leur entrée Node. Un partenaire ne connaît pas l'Utilisateur : le dépôt
est rangé sous `emergency_pub = sig_pub_emergency`, que partagent tous ses
Connecteurs.

```
--8<-- "network/EmergencyCredential.table.md"
```
```
--8<-- "network/EmergencyPut.table.md"
```

**Anti-abus** : `EmergencyPut` exige un `EmergencyCredential` — preuve VDF
de `0x00 ‖ sig_pub_user` (comme
[`Attach`](partenariat-automatique.md#rattachement-automatique-des-utilisateurs))
et signature de `sig_priv_user` sur
`L("s3m/sig/emergency-deposit/v1") ‖ emergency_pub ‖ L(peer_demandeur) ‖ L(peer_partenaire)`.
Une identité VDF ne tient qu'une `emergency_pub` à la fois chez un
partenaire (une autre est refusée, `QuotaExceeded`, tant que la première a
des blocs). Le partenaire applique sa réserve : au plus `U_backup`
déposants, `E_secours` octets au total, `Q_max / n_secours` par déposant ;
au-delà, `QuotaExceeded`. Réponse `Stored` (`hash = SHA-256(data)`). Les
blocs sont rangés sous le propriétaire `EmergencyDepositor`
([`protocols.stockage-physique`](stockage-physique.md)).

```
--8<-- "network/EmergencyGet.table.md"
```

**Relecture** : `EmergencyGet`, sans identifiant — les blocs sont chiffrés
`K_block` et leurs hashes impossibles à deviner. Le partenaire ne sert que
les blocs rangés sous cette `emergency_pub` ; débit limité comme le
[secours](echange-blocs.md#autorisation-de-secours) (64 par seconde et par
`emergency_pub`, rafale 256). Réponse `BlockData`.

```
--8<-- "network/EmergencyRelease.table.md"
```

**Libération** : `EmergencyRelease`, signé par `sig_priv_emergency` — tout
Connecteur de l'Utilisateur peut l'émettre. Le partenaire vérifie la
signature avec `emergency_pub`, refuse un `timestamp` non plus récent que
le dernier appliqué (`Replayed`), supprime les blocs listés et répond
`Ack` (`freed`). Un déposant sans blocs sort de la réserve. Des blocs
jamais libérés sont supprimés **15 552 000 s** après le dernier dépôt
(durée de vie de l'entrée DHT).

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
déchiffre l'entrée (il connaît `K_attach`), récupère les blocs absents par
`EmergencyGet` chez les partenaires listés, recalcule/disperse la parité normalement — étape
purement mécanique sur des blocs opaques, sans Connecteur. Seul traitement
réel : le respect du quota
([`node.UserQuota`](../02-schemas/node/UserQuota.md)), rejet par timestamp
croissant exactement comme [`protocols.quota-sync`](quota-sync.md).

## Découverte et réconciliation FS {: #decouverte-et-reconciliation }

Autonome côté Connecteur : n'importe quel Connecteur de l'Utilisateur peut
re-dériver `emergency_dht_key` et consulter la DHT. Vérification de
présence des blocs avant envoi des mutations FS — jamais de mutation
référençant un bloc manquant.

Réconciliation : la mutation de racine est validée par `CommitRoot`
(`base_root = base_fs_root_hash`) une fois ses blocs présents sur le Nœud
(intégrés par lui, ou renvoyés par le Connecteur qui les détient). Un
refus est un conflit traité comme dans
[`protocols.write-queue`](write-queue.md). Une fois la réconciliation FS
confirmée, les partenaires de secours reçoivent un
[`EmergencyRelease`](#depot) libérant l'espace réservé.
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
**E_secours = 20 GiO** — ~1% pour un Nœud de 2 To. `U_backup` est réglable
dans le dashboard du Nœud, qui affiche aussi les déposants accueillis et
l'espace occupé ; celui du Connecteur affiche l'état de l'écriture
d'urgence ([`deploiement.packaging`](../07-deploiement/packaging.md)).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
