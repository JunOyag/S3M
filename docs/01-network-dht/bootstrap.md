---
id: network.bootstrap
kind: narrative
title: "Amorçage (Bootstrapping) & Résolution"
section: "§2.2"
status: draft
verified_by: []
---

# Amorçage (Bootstrapping) & Résolution

Amorçage initial d'un nouveau nœud via les protocoles de rendez-vous
libp2p (Rendezvous Protocol / STUN / TURN).

## Chemin rapide (cache local présent)

Le Connecteur interroge en priorité son cache `UserManifest` local pour
obtenir directement l'ID de son nœud hébergeur et le dernier `fs_root_hash`
connu.

**Avant d'utiliser ce cache**, il compare systématiquement son timestamp
local à celui de l'entrée DHT User courante
([`network.dht-directory`](dht-directory.md)) : si cette dernière est plus
récente, cela signale qu'un **autre Connecteur du même Utilisateur** a écrit
depuis — le Connecteur adopte alors le `fs_root_hash` de l'entrée DHT comme
référence à jour, cohérent avec la détection de conflit par
`base_fs_root_hash` de la [`fs.WriteQueue`](../02-schemas/fs/WriteQueue.md)
(voir [`protocols.write-queue`](../04-protocols/write-queue.md)).

En cas d'indisponibilité du nœud local malgré un cache présent, le
Connecteur résout directement l'adresse du nœud et le bloc racine actif via
la DHT.

## Chemin d'amorçage à froid (nouvelle machine, même seed)

Aucun état local préexistant n'est requis — seule la seed BIP-39 suffit
(chemins de dérivation :
[`crypto.identity-derivation`](../03-crypto/identity-derivation.md)) :

1. Calcul de `user_dht_key = KDF(priv_user, pub_user, "dht-lookup")` depuis
   la seed seule.
2. Résolution de l'entrée DHT User.
3. Déchiffrement avec `K_self` ([`crypto.k-self`](../03-crypto/k-self.md))
   pour obtenir `fs_root_hash` et l'historique `attachments` (donc le
   `node_id` du Node courant).
4. Contact de ce Node pour récupérer le bloc racine et reconstruire un
   `UserManifest` local à jour.

Cohérent avec la procédure de disaster recovery complète — voir
[`deploiement.disaster-recovery`](../07-deploiement/disaster-recovery.md).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
