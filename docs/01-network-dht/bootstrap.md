---
id: network.bootstrap
kind: narrative
title: "Amorçage (Bootstrapping) & Résolution"
section: "§2.2"
status: draft
verified_by: []
---

# Amorçage (Bootstrapping) & Résolution

Entrée dans le réseau : le Connecteur (client, voir
[`network.dht-directory`](dht-directory.md)) se connecte à une **liste de
Nœuds d'amorçage fournie par sa configuration**. La traversée de NAT
(Rendezvous / STUN / TURN) est une fonctionnalité séparée
([`network.traversee-nat`](traversee-nat.md), ajoutée le 2026-11-20), à spécifier plus
tard (arbitrage du 2026-11-19, `impl/SPEC_GAPS.md`).

## Découverte sur le réseau local {: #reseau-local }

Ajout du 2026-11-20. Chaque Nœud s'annonce sur le réseau local par **mDNS**
(libp2p, désactivable par `mdns: false`) ; les Nœuds découverts ainsi
entrent aussi dans sa table DHT. L'assistant de premier lancement du
Connecteur ([`deploiement.packaging`](../07-deploiement/packaging.md#barre-des-taches))
écoute ces annonces quelques secondes, vérifie chaque candidat par un
`Probe` ([`protocols.echange-blocs`](../04-protocols/echange-blocs.md)) et
propose la liste ; le `node_id` se déduit du `PeerId` annoncé. L'annonce ne
révèle que la présence d'un Nœud S3m et son adresse locale.

Un Nœud encore sous [identité temporaire](../07-deploiement/appairage-admin.md#temporaire)
s'annonce de même, avec cette identité, sur son port d'administration ; il
ne répond pas au `Probe` mais au `hello` du canal d'administration
(`mode: setup`), et l'assistant le liste comme « à configurer ».

**Nœud qui change d'adresse** (box, DHCP, autre réseau) : un Connecteur dont
le Nœud reste injoignable, y compris aux adresses de son entrée DHT, le
recherche sur le réseau local par son identité (même `node_id`), au plus
toutes les 2 minutes. L'adresse qui répond est retenue (fichier `node.addr`
des données du Connecteur, ignoré s'il désigne un autre `PeerId`) et
préférée au démarrage suivant ; la configuration n'est pas réécrite.

**Annuaire sans le Nœud** (ajout du 2026-11-24) : le Nœud est souvent le
seul Nœud d'amorçage DHT d'un Connecteur. Tant que l'annuaire répond, le
Connecteur garde (fichier `dht_peers.json`, 32 adresses au plus) les
adresses des partenaires de son catalogue de dispersion et celles de sa
table de routage ; il s'en sert comme Nœuds d'amorçage supplémentaires au
démarrage, et les ajoute — avec les autres Nœuds trouvés sur le réseau
local — quand son Nœud est hors ligne. L'écriture d'urgence
([`protocols.espace-secours`](../04-protocols/espace-secours.md)) et la
lecture de secours ([`protocols.integrite-lecture`](../04-protocols/integrite-lecture.md#noeud-hors-ligne))
restent ainsi possibles.

## Chemin rapide (cache local présent)

Le Connecteur interroge en priorité son **cache local** pour obtenir
directement l'ID de son nœud hébergeur et le dernier `fs_root_hash` connu.
Ce cache est minimal : `node_id`, `fs_root_hash` et l'horodatage de l'entrée
DHT User dont il provient (fichier binaire local
`u16be(1) ‖ node_id ‖ u64be(timestamp) ‖ u32be(len) ‖ fs_root_hash`).

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

1. Calcul de `user_dht_key = KDF(priv_user, "dht-lookup", —, pub_user)`
   ([convention KDF](../03-crypto/symmetric-suite.md#kdf-hkdf-sha256)) depuis
   la seed seule.
2. Résolution de l'entrée DHT User.
3. Déchiffrement avec `K_self` ([`crypto.k-self`](../03-crypto/k-self.md))
   pour obtenir `fs_root_hash` et l'historique `attachments` ; le Node
   courant est l'attachement au `timestamp` le plus récent. Son entrée DHT
   donne son adresse ; un `migration_pointer` valide y est suivi d'un seul
   saut ([`securite.incidents-compromissions`](../05-securite/incidents-compromissions.md)).
4. Contact de ce Node pour récupérer le bloc racine et reconstruire le cache
   local. Cette étape dépend du protocole d'échange de blocs
   Connecteur ↔ Nœud, défini par
   [`protocols.acces-applicatif`](../04-protocols/acces-applicatif.md) : elle
   est implémentée avec lui (Phase 4), pas par cet id.

Cohérent avec la procédure de disaster recovery complète — voir
[`deploiement.disaster-recovery`](../07-deploiement/disaster-recovery.md).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
