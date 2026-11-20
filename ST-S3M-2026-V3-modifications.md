# Modifications de spécification — ST-S3M-2026-V2 → V3 (proposition)

> **Intégré le 2026-11-19** dans `docs/` (branche `docs/spec-v3`). Les points ⚠ et ❓
> ont été arbitrés : voir l'entrée « Spec V3 » de `impl/SPEC_GAPS.md`, qui fait foi
> en cas d'écart avec ce document (notamment λ = 1024, `K_wrap`, `K_dispersal_block`,
> `priv_node_recovery`). Ce fichier est conservé comme trace de la proposition.

**Document de référence :** ST-S3M-2026-V2 (05 Sept 2026)
**Objet :** texte de remplacement section par section, résultant des décisions prises en session. À intégrer tel quel dans la spécification, puis à répercuter dans les pages d'implémentation (`status.yml`, `impl/TECH_STACK.md`, `vdf-verifier-pure.md`, `deploiement.packaging`).

**Légende**

- ✅ **Décidé** en session.
- ⚠ **Précision ajoutée à la rédaction** : non tranchée explicitement, proposée pour rendre le texte implémentable. À confirmer avant le gel des vecteurs de test.
- ❓ **Point ouvert** découvert à la rédaction : à trancher avant d'implémenter la partie concernée (§12).

---

## 0. Index des changements

| Section V2 | Nature du changement | Décisions |
|---|---|---|
| En-tête `STACK` | Ajout Rust (moteur du Connecteur), lecteur monté natif | ✅ |
| §2.1 | Δ par identité, identité marquée `key_algorithm \|\| clé` | ✅ |
| §3.8 | Convention HKDF ; `K_block` dérivé de la position ; format de bloc ; borne AEAD | ✅ ⚠ ❓ |
| §3.9 | Enveloppe signée ; TTL en secondes ; lissage ; `seq` ; plus de suppression de l'`EmergencyManifest` ; tags de clé | ✅ ⚠ ❓ |
| §3.11 | Nouveaux schémas FlatBuffers (entrées DHT, plaintext User, `migration_pointer`) | ✅ ⚠ |
| §3.12 | Lecteur monté natif à la place de WebDAV | ✅ |
| §3.12.2 | Budgets disque indépendants | ✅ |
| §3.12.4 | `EmergencyManifest` : séquence, lecture-fusion-écriture, pas de suppression | ✅ |
| §3.12.5 (nouveau) | Écriture par plages et synchronisation différée | ✅ ⚠ |
| §3.13 | Sel neuf à chaque réémission, chiffrement du dernier bloc vers le premier, capacité utile | ✅ ⚠ |
| §5.2 | Format et règles du `migration_pointer` | ✅ ⚠ |
| §7.3 | Binaire Rust natif, dashboard statique, protections de l'API locale | ✅ ⚠ |

---

## 1. En-tête `STACK` et historique du document

**Remplacer** la ligne `STACK` par :

```
**STACK :** libp2p / Kademlia / Reed-Solomon / VDF (Wesolowski) / FlatBuffers / HKDF-SHA-256 / ChaCha20-Poly1305 / Rust (Nœud et moteur du Connecteur) / WinFsp-FUSE (lecteur monté) / Docker
```

**Ajouter** à la suite de l'historique des révisions : `… : V3 — Δ par identité, convention HKDF, K_block dérivé de la position, enveloppe signée DHT, séquences monotones (EmergencyManifest, migration_pointer), TTL en secondes, lecteur monté natif et écriture différée, moteur du Connecteur en Rust`.

---

## 2. §2.1 — Génération d'identité

### 2.1 Remplacer le paragraphe « Setup » par

> **Setup — un discriminant `Δ` par identité.** Le groupe utilisé est la classe de formes quadratiques imaginaires `Cl(Δ)`, avec `Δ = -p` négatif, où `p` est un nombre premier `p ≡ 3 mod 4` supérieur à `2^λ` (λ = niveau de sécurité, ex. 2048 bits). Contrairement à un groupe RSA, l'ordre de `Cl(Δ)` est structurellement inconnu de quiconque : aucune cérémonie de confiance n'est requise.
>
> `Δ` n'est **pas** un paramètre de genèse : il est dérivé de façon publique et déterministe **de l'identité elle-même**, par la procédure définie dans `vdf-identity.md` (point de départ : `SHA-256` de l'identité, puis recherche du premier candidat premier convenable). N'importe quel vérificateur rejoue cette dérivation. Un paramètre de difficulté `T` est calibré pour ~1 minute de calcul sur une machine de référence.

### 2.2 Ajouter la définition de l'identité (nouveau paragraphe, avant « Calcul séquentiel »)

> **Identité marquée.** L'« identité » hachée par la VDF est la séquence d'octets `key_algorithm (1 octet) || clé publique brute` (§3.9, §8.4). Pour l'algorithme 0, c'est `0x00 || pub_key` (33 octets). Le même tag est porté par l'enveloppe qui transporte la preuve ; un tag différent entre les deux est une erreur (§3.9).

### 2.3 Remplacer le dernier point (« Le tuple de preuve d'identité n'a donc pas besoin de porter `Δ` … ») par

> **Le tuple de preuve ne porte pas `Δ`** : le vérificateur le dérive de l'identité. Seul `(identité, y, π)` est joint à toute nouvelle entrée DHT Node ou User. `T` et la procédure de mise en groupe (`H → Cl(Δ)`) restent fixés par cette spécification.
>
> **Coût côté vérificateur.** La dérivation de `Δ` (recherche d'un premier de λ bits) fait partie du coût de vérification et n'est pas négligeable. Ce choix est assumé ; il sera rouvert si les mesures par phase (dérivation de `Δ`, hachage vers la forme, évaluation, preuve, vérification) montrent que cette étape domine.

### 2.4 Autres références à corriger

- §2.1, début : la phrase « (paramètre de genèse, identique pour toute la spec — pas régénéré par identité) » est supprimée.
- §1, « Sécurité des Identités » : aucun changement de fond.
- §5.3, note de conception : aucun changement de fond.

---

## 3. §3.8 — Chiffrement

### 3.1 Nouveau sous-paragraphe en tête de §3.8 : « Convention de dérivation (KDF) »

> **Toute dérivation `KDF(…)` de ce document est un HKDF-SHA-256 (RFC 5869)** instancié ainsi :
>
> ```
> KDF(secret, label, [salt], [entrées publiques…]) :=
>   HKDF( IKM  = secret,
>         salt = salt, ou chaîne vide s'il n'y en a pas,
>         info = "s3m/kdf/v1" || L(label) || L(entrée_1) || L(entrée_2) || …,
>         L    = 32 octets )
> avec L(x) = longueur de x sur 4 octets big-endian, suivie de x
> ```
>
> - Le **secret** est toujours l'IKM ; les entrées publiques (`pub_user`, index de bloc…) vont dans `info`, jamais dans l'IKM.
> - La sortie de 32 octets sert directement de clé symétrique, ou de **graine Ed25519** (forme RFC 8032) pour les clés de signature.
> - Les libellés ci-dessous sont ceux déjà utilisés dans ce document, inchangés.
>
> ⚠ La largeur du préfixe de longueur (4 octets) et la chaîne `"s3m/kdf/v1"` sont proposées ici ; elles doivent être figées avant la génération des vecteurs de test.

| Clé | Secret (IKM) | Label | Sel | Entrées publiques |
|---|---|---|---|---|
| `user_dht_key` | `priv_user` | `"dht-lookup"` | — | `pub_user` |
| graine de `sig_priv_user` | `priv_user` | `"dht-signing"` | — | `pub_user` |
| `K_self` | `priv_user` | `"attachment-recovery"` | — | — |
| `K_node_self` | `priv_node` | `"node-recovery"` | — | — |
| graine de `priv_node_recovery` | seed BIP-39 du Nœud | `"node-recovery-signing"` | — | — |
| `K_attach` | secret partagé X25519 | `"attach"` ⚠ | `salt` d'attachement | — |
| `K_dispersal_content` | `K_attach` | `"dispersal-content"` | — | — |
| graine de `sig_priv_dispersal` | `K_attach` | `"dispersal-signing"` | — | — |
| `K_emergency_content` | `K_attach` | `"emergency-content"` | — | — |
| graine de `sig_priv_emergency` | `K_attach` | `"emergency-signing"` | — | — |
| `K_block` | `master_key[version]` | `"block"` | `encryption_salt` | index du bloc (u32 big-endian) |
| `K_dispersal_block` | `K_dispersal_content` | `"dispersal-block"` | — | ❓ voir §12, point 1 |

⚠ Le label `"attach"` n'existait pas dans la V2 (`K_attach = KDF(X25519(…), salt)`) ; il est ajouté pour la séparation de domaines.

### 3.2 Remplacer le paragraphe `K_block` par

> **`K_block` — contenu réel des blocs**
>
> ```
> K_block = KDF(master_key[version], "block", encryption_salt, index_du_bloc)
> ```
>
> - Dérivée uniquement de la seed BIP-39 du User — jamais partagée avec le Nœud.
> - **`K_block` ne dépend pas du `block_hash`.** Le `block_hash` est le hash du texte chiffré ; en dépendre créerait une circularité (il faudrait connaître le hash d'un bloc pour le chiffrer). La clé dépend de la **position** du bloc dans la chaîne (`index_du_bloc`, de 0 pour le premier bloc de la chaîne) et du `encryption_salt` de la version du fichier ou du répertoire.
> - **`encryption_salt` est neuf (16 octets d'un CSPRNG) à chaque création ou réémission** d'un fichier ou d'un répertoire, et il est porté par l'entrée FS correspondante (§3.13). **Règle impérative : un `encryption_salt` n'est jamais réutilisé pour un contenu différent.** Une écriture interrompue puis reprise repart avec un nouveau sel.
> - **Granularité de révocation :** une clé distincte par version de fichier (sel) et par position, et non plus par bloc isolé. Révoquer une version revient à supprimer ses blocs (§4.3).
> - Le Connecteur chiffre les blocs avec `K_block` **avant même l'envoi au Nœud**. Le Nœud calcule les blocs de parité Reed-Solomon directement sur le texte chiffré (opération linéaire) et **ne détient ni ne dérive jamais `K_block`**. Le hash de challenge PoS (§5.3.2) et le contrôle d'intégrité (§3.12.1) portent toujours sur le texte chiffré.
> - Le paragraphe sur la double présence de `key_version` (`BlockEntry` et entrée FS) est conservé tel quel.

### 3.3 Nouveau sous-paragraphe : « Format d'un bloc chiffré »

> Chaque bloc de données stocké fait exactement **65 536 octets** :
>
> ```
> version (2 octets) || nonce (12 octets, aléatoire) || ciphertext || tag (16 octets)
> ```
>
> - AEAD : **ChaCha20-Poly1305**, clé `K_block`.
> - Le contenu en clair (`ciphertext` après chiffrement) fait donc `65 536 − 2 − 12 − 16 = 65 506` octets. Le `FileBlock` ou le `DirectoryBlock` sérialisé (FlatBuffers) est complété par du padding à zéro à droite jusqu'à cette taille.
> - ⚠ Données associées authentifiées (AAD) : l'en-tête de version de 2 octets.
> - Le même format `nonce || ciphertext || tag` est utilisé pour les blobs chiffrés des entrées DHT (§3.9) : un seul code AEAD.
> - La capacité utile d'un `FileBlock` (`FILE_BLOCK_DATA_BYTES`) est mesurée par un test : plus grande taille de `data` pour laquelle le `FileBlock` sérialisé (avec `next_hash` et surcoût FlatBuffers) tient dans 65 506 octets. L'ordre de grandeur attendu est d'environ 65 400 octets.

### 3.4 Nouveau sous-paragraphe : « Borne d'usage des clés AEAD »

> Aucune clé AEAD de ce protocole ne chiffre un nombre de messages proche de la limite usuelle de 2^32 pour un nonce aléatoire de 96 bits :
> - `K_block` : un seul message par clé (une clé par version de fichier et par position).
> - `K_self`, `K_node_self`, `K_attach` et ses dérivées : un message par publication ou republication, soit de l'ordre de quelques milliers sur toute la vie d'une identité.
>
> **Aucun compteur persistant n'est donc spécifié** : un compteur local ne serait pas reconstructible depuis la seule seed (§7.1) et n'apporterait qu'une fausse assurance après restauration.

### 3.5 Autres corrections dans §3.8

- Paragraphe « Continuité de chiffrement » : remplacer « dérive `K_block = KDF(master_key[version], block_hash, encryption_salt)` » par la formule du §3.2 ci-dessus (sel et index).
- Paragraphe `K_dispersal_content` / `K_dispersal_block` : voir le point ouvert §12.1 avant de modifier.
- Dans toute la spec, les mentions de « clé distincte par `block_hash` » (§3.8, §3.13, §3.11) sont à remplacer par « clé distincte par version de fichier et par position ».

---

## 4. §3.9 — Entrées DHT

### 4.1 Nouveau paragraphe : « Enveloppe signée »

> **Toute entrée DHT est transportée dans une enveloppe `DhtEnvelope`** (§3.11) : `{key_algorithm, payload, signature}`.
> - `payload` est la sérialisation FlatBuffers de l'entrée (`NodeEntry`, `UserEntry`, `DispersalEntry` ou `EmergencyEntry`).
> - `signature` est une **signature Ed25519 portant sur les octets exacts de `payload` tels que transmis**. Le vérificateur contrôle ces octets reçus : il ne réserialise jamais. Le champ de signature n'est donc pas dans le buffer signé.
> - La clé de vérification est celle de l'entrée : `pub_node` pour une entrée Node (clé de recherche), `sig_pub_user` pour une entrée User, `sig_pub_dispersal` ou `sig_pub_emergency` pour les deux autres, publiées en clair dans le payload.
> - **Tags `key_algorithm`.** Seul le tag **0** (Ed25519/X25519) est accepté. Les tags 1 (ML-DSA/ML-KEM) et 2 (hybride) sont reconnus et rejetés par une erreur dédiée « algorithme non supporté », distincte de « signature invalide ». Un tag différent entre l'identité marquée (VDF, §2.1) et l'enveloppe est rejeté comme incohérent. Un tag inconnu (ex. 255) est rejeté.
> - ⚠ Chaque payload et chaque blob chiffré porte un libellé de protocole propre au type d'entrée dans ses AAD (voir §3.3 de ce document : `nonce || ciphertext || tag` avec AAD = libellé du type d'entrée suivi de `schema_version` en u16 big-endian).

### 4.2 Remplacer le paragraphe « Expiration & republication » par

> **Durées de vie (en secondes, constantes de protocole).** Les durées sont exprimées en secondes fixes ; « 6 mois », « 1 an » et « 10 ans » ne sont que des raccourcis de rédaction :
>
> | Raccourci | Valeur | Secondes |
> |---|---|---|
> | « 6 mois » | 180 jours | 15 552 000 |
> | « 1 an » | 365 jours | 31 536 000 |
> | « 10 ans » | 3 650 jours | 315 360 000 |
> | période de republication (« mensuelle ») | 30 jours | 2 592 000 |
>
> Les entrées portent trois régimes :
> - **Node et DispersalManifest** : durée de vie de 15 552 000 s, republiées à chaque période de 2 592 000 s avec un timestamp signé à jour (contenu inchangé possible).
> - **EmergencyManifest** : durée de vie de 15 552 000 s, **sans republication périodique et sans suppression**. L'entrée n'est jamais effacée : elle expire à l'issue de cette durée (voir §3.12.4).
> - **User** : durée de vie de 315 360 000 s. Republication **réactive** à chaque écriture confirmée qui change `fs_root_hash`, et **de secours** après 31 536 000 s sans écriture.
>
> **Lissage des republications.** Pour éviter un pic de charge, chaque republication est décalée :
>
> ```
> offset_s = entier_big-endian( SHA-256( identifiant_en_octets_bruts ) ) mod 2 592 000
> ```
>
> - Entrée Node : identifiant = `pub_node` (octets bruts).
> - `DispersalManifest` d'un couple (User, Node) : identifiant = `user_id || node_id` (concaténation d'octets bruts, `user_id = pub_user`).
> - ⚠ La republication a lieu aux instants Unix `t` tels que `t ≡ offset_s (mod 2 592 000)`. L'ancrage sur l'époque Unix est proposé ici.

### 4.3 Remplacer la ligne `EmergencyManifest` du tableau des champs publiés par

> **EmergencyManifest** (par `user_id`, indépendant du Nœud) : clé de recherche `emergency_dht_key = H(K_attach || "emergency")` ; payload `EmergencyEntry` contenant `sig_pub_emergency` (en clair), `seq`, `timestamp` et `Encrypt(K_emergency_content, EmergencyManifest)` ; enveloppe signée avec `sig_priv_emergency`. Écrit par n'importe quel Connecteur du même `user_id` selon la règle de séquence du §3.12.4 ; lu et réconcilié par n'importe quel Connecteur ; intégré mécaniquement par le Nœud. Durée de vie 15 552 000 s, pas de republication, pas de suppression.

### 4.4 Autres corrections dans §3.9

- Paragraphe « Signature sans exposer `pub_user` » : la graine de `sig_priv_user` est la sortie HKDF du §3.1, utilisée comme graine Ed25519.
- La ligne User du tableau : durée de vie « 10 ans » devient « 315 360 000 s » ; « 1 an d'inactivité » devient « 31 536 000 s ».
- Dernière phrase du paragraphe « Expiration & republication » (« à ceci près que l'EmergencyManifest n'est … jamais republié ») : supprimer la mention de suppression, voir §3.12.4.
- ❓ La clé qui porte la preuve VDF d'une entrée User est à préciser : voir §12.2.

---

## 5. §3.11 — Schémas FlatBuffers

### 5.1 Ajouter

```fbs
// ---- DhtEntries.fbs ----
// Entrées DHT. Chaque entrée est transportée dans une DhtEnvelope (§3.9) ;
// la signature Ed25519 porte sur les octets exacts de `payload`.
include "DispersalManifest.fbs";   // Partner, MasterKeyEntry
namespace S3m.Dht;

table DhtEnvelope {
  key_algorithm: uint8;           // 0 = Ed25519 (seul accepté, §3.9)
  payload: [ubyte];               // sérialisation FlatBuffers de l'entrée, signée telle quelle
  signature: [ubyte];             // Ed25519 (64 octets), sur les octets exacts de `payload`
}

table VdfProof {
  identity: [ubyte];              // key_algorithm (1 octet) || clé publique brute (§2.1)
  y: [ubyte];
  pi: [ubyte];
}

// Migration d'identité du Nœud (§5.2). Enveloppe propre, signée par priv_node_recovery.
table MigrationPointerPayload {
  old_node_id: [ubyte];
  new_node_id: [ubyte];
  seq: uint64;                    // monotone, commence à 1 (§5.2)
  timestamp: uint64;
}
table SignedMigrationPointer {
  payload: [ubyte];               // sérialisation de MigrationPointerPayload
  signature: [ubyte];             // Ed25519 sur "s3m/migration-pointer/v1" || payload  ⚠
}

table NodeSnapshotPointer {       // plaintext chiffré avec K_node_self
  node_snapshot_root_hash: [ubyte];
  node_snapshot_root_partners: [S3m.Dispersal.Partner];
}

table NodeEntry {
  ip: string;
  port: uint16;
  timestamp: uint64;              // preuve d'identité (signature de l'enveloppe par pub_node)
  vdf_proof: VdfProof;
  pub_node_recovery: [ubyte];     // immuable (§5.2)
  migration_pointer: SignedMigrationPointer;  // optionnel (§5.2)
  snapshot_ciphertext: [ubyte];   // nonce || ciphertext || tag de NodeSnapshotPointer sous K_node_self
}

table AttachmentRecord {
  node_id: [ubyte];
  salt: [ubyte];
  timestamp: uint64;
  inactivity_detected_at: uint64; // 0 si sans objet (§3.8)
  key_algorithm: uint8;           // 0 par défaut (§8.4)
  kem_ciphertext: [ubyte];        // vide si key_algorithm = 0 (§8.2)
  wrapped_shared_secret: [ubyte]; // vide si key_algorithm = 0 (§8.2)
}

table UserEntryPlaintext {        // plaintext chiffré avec K_self
  fs_root_hash: [ubyte];
  encryption_salt: [ubyte];       // du répertoire racine (§3.2, §3.13)
  key_version: uint16;
  attachments: [AttachmentRecord];
  master_key_chain: [S3m.Dispersal.MasterKeyEntry];
  schema_version: uint16;
}

table UserEntry {
  sig_pub_user: [ubyte];          // auto-certifiant (§3.9)
  timestamp: uint64;
  vdf_proof: VdfProof;            // ❓ identité à préciser (§12.2)
  ciphertext: [ubyte];            // nonce || ciphertext || tag de UserEntryPlaintext sous K_self
}

table DispersalRootPointer {      // plaintext chiffré avec K_attach
  dispersal_root_hash: [ubyte];
  dispersal_root_partners: [S3m.Dispersal.Partner];
}

table DispersalEntry {
  sig_pub_dispersal: [ubyte];     // en clair (§3.9)
  timestamp: uint64;
  ciphertext: [ubyte];            // nonce || ciphertext || tag de DispersalRootPointer sous K_attach
}

table EmergencyEntry {
  sig_pub_emergency: [ubyte];     // en clair, pour que les pairs vérifient les mises à jour
  seq: uint64;                    // monotone (§3.12.4), en clair pour être contrôlé sans déchiffrement
  timestamp: uint64;
  ciphertext: [ubyte];            // nonce || ciphertext || tag de EmergencyManifest sous K_emergency_content
}
```

⚠ Un `file_identifier` FlatBuffers par type d'entrée (ex. `"NODE"`, `"USER"`, `"DISP"`, `"EMRG"`) est recommandé pour qu'un payload ne soit jamais décodé sous un mauvais type ; il n'a pas été tranché explicitement.

### 5.2 Corrections dans les schémas existants

- `FileSystemEntry.fbs`, commentaire de `DirectoryEntry.encryption_salt` : « neuf à chaque réémission du fichier ou du répertoire ; avec `key_version` et l'index du bloc, dérive `K_block` (§3.8) ».
- `NodeConfig` : ajouter, en champs additifs, `write_back_min_delay_seconds`, `write_back_max_delay_seconds` et `workspace_reserve_bytes` côté Connecteur (§3.12.5) ; ces champs relèvent de la configuration du Connecteur, pas de celle du Nœud, et sont donc à porter dans la configuration locale du Connecteur plutôt que dans `NodeConfig`.

---

## 6. §3.12 — Accès applicatif : lecteur monté natif

### 6.1 Remplacer le premier point de §3.12 (WebDAV)

> - Le Connecteur expose les données de l'utilisateur sous forme d'un **lecteur monté natif**, via un pilote de système de fichiers en espace utilisateur, derrière un **trait de système de fichiers commun** dans le moteur : **WinFsp** sous Windows, **FUSE** sous Linux, puis macOS (macFUSE ou FUSE-T, choix à trancher à ce moment). Le moteur n'a qu'une implémentation de la logique de fichiers ; chaque système fournit son backend. **Aucun service réseau n'est exposé pour l'accès aux fichiers.**
> - La première version vise Windows (WinFsp) ; les backends FUSE s'ajoutent ensuite sans modifier le moteur.
> - **Prérequis d'installation** : WinFsp (Windows) ou FUSE (Linux, macOS). Le Connecteur n'est plus un exécutable entièrement autonome.

### 6.2 Autres corrections

- Toutes les occurrences de « WebDAV » dans la spec (§3.12, §7.3, historique) sont remplacées par « lecteur monté ».
- Le « Chemin normal » et le « Chemin de secours » restent inchangés dans leur principe.

### 6.3 §3.12.2 — Ajouter à la fin du point « Taille limite »

> Le budget `Q_max` de la `WriteQueue` et l'**espace de travail** de reconstitution des fichiers (§3.12.5) sont **deux budgets indépendants**. Le second est plafonné par l'espace disque local libre moins une réserve réglable (`workspace_reserve_bytes`), et non par `Q_max`.

---

## 7. §3.12.4 — Espace de secours : séquence, fusion, pas de suppression

### 7.1 Remplacer le paragraphe « Pointeur de secours » (dernière partie, publication)

> L'`EmergencyManifest` est publié sous `emergency_dht_key = H(K_attach || "emergency")`, dans une `EmergencyEntry` (§3.11) signée avec `sig_priv_emergency`. **Comme tous les Connecteurs d'un même `user_id` partagent cette clé et cette signature, l'écriture suit une règle de séquence monotone :**
> 1. Le Connecteur lit l'entrée courante (s'il y en a une) et note son `seq`.
> 2. Il **fusionne** les blocs, partenaires et mutations déjà présents avec les siens, sans en perdre aucun.
> 3. Il publie l'entrée fusionnée avec `seq + 1`.
> 4. **Les pairs DHT rejettent toute entrée dont `seq` est inférieur ou égal à celui qu'ils détiennent.** Si deux Connecteurs écrivent simultanément avec la même séquence, l'un est rejeté : il relit, fusionne et réessaie.
>
> Cela évite à la fois l'écrasement des références aux blocs déposés par un autre Connecteur et le rejeu d'une ancienne version validement signée.

### 7.2 Remplacer la phrase finale « Une fois la réconciliation FS confirmée, l'`EmergencyManifest` est supprimé et … »

> Une fois la réconciliation FS confirmée, les partenaires de secours reçoivent un ordre de tombstone (§4.3) libérant l'espace réservé. **L'entrée DHT `EmergencyManifest` n'est pas supprimée** : il n'existe pas d'opération de suppression pour cette entrée ; elle expire à l'issue de sa durée de vie (15 552 000 s, §3.9). Tout Connecteur qui la redécouvre après réconciliation doit traiter la réconciliation comme **idempotente** : la comparaison par `base_fs_root_hash` (§3.12.2) et la vérification de présence des blocs sur le Nœud (ci-dessous) suffisent à ne rien réappliquer à tort.

### 7.3 Corrections induites

- Paragraphe « Surveillance multi-Connecteurs » : l'entrée étant unique par `user_id` et fusionnée, l'estimation du quota engagé par les autres Connecteurs se lit désormais dans cette entrée unique, plus dans des entrées distinctes.
- §3.9, ligne EmergencyManifest et dernier alinéa : voir §4.2, §4.3 de ce document.
- §6 (tableau « Procédures de secours »), ligne « Nœud seul injoignable » : « réintégration automatique au retour du Nœud », sans changement ; ajouter « entrée DHT expirant à 6 mois, jamais supprimée ».

---

## 8. §3.12.5 (nouveau) — Écriture par plages et synchronisation différée

> Un programme écrit dans un fichier du lecteur monté **par plages d'octets**, alors que les blocs sont immuables et chaînés par hash (§3.13) : modifier un fichier crée une nouvelle chaîne complète et supprime l'ancienne. Le chiffrement d'une chaîne se fait du **dernier bloc vers le premier** (chaque bloc contient le `next_hash` du suivant, §3.13) : aucun bloc ne peut partir avant que le fichier entier soit disponible en local.
>
> - **Copie locale reconstituée.** À la première écriture sur un fichier existant, le Connecteur reconstitue le fichier **en entier** dans un **espace de travail local** avant d'accepter l'écriture. Les écritures suivantes s'appliquent à cette copie. La taille maximale d'un fichier modifiable est donc bornée par l'espace de travail disponible ; s'il manque, le lecteur renvoie l'erreur standard « disque plein » et le dashboard affiche l'occupation de l'espace de travail (§3.12.2 pour l'indépendance avec `Q_max`).
> - **Durabilité locale.** La copie reconstituée est écrite sur disque et journalisée (même principe que la `WriteQueue`, §3.12.2). Un plantage ou un redémarrage ne perd pas les modifications ; les synchronisations en attente reprennent au lancement.
> - **Délai de silence (debounce).** La synchronisation d'un fichier modifié est différée : le minuteur du fichier redémarre à chaque écriture et la synchronisation ne part qu'après une période sans nouvelle écriture :
>
>   ```
>   D = clamp( 60 s + 0,5 s × taille_du_fichier_en_MiO , 60 s , 300 s )
>   ```
>
>   (1 MiO ≈ 1 min ; 100 MiO ≈ 1 min 50 s ; plafond de 5 min dès 480 MiO.)
> - **Attente maximale.** Quelle que soit l'activité, la synchronisation part au plus tard **15 minutes** après la première écriture non synchronisée, pour éviter qu'un programme qui écrit en continu (journal, base de données) ne la repousse indéfiniment.
> - **Paramétrage.** Le délai minimum, le plafond de `D`, l'attente maximale et la réserve de l'espace de travail sont réglables dans le dashboard du Connecteur.
> - **Fermeture, flush, `fsync`.** Ces opérations rendent la copie locale durable mais **ne déclenchent pas** la synchronisation. Une synchronisation immédiate n'a lieu qu'au démontage, à l'arrêt propre du Connecteur, ou sur action « synchroniser maintenant » du dashboard.
> - **Lecture pendant le délai.** Le lecteur sert la version locale modifiée, pour que l'utilisateur voie ses changements immédiatement.
> - **Exposition.** Tant que la synchronisation n'a pas eu lieu, la modification n'existe que sur le disque local (ni chez le Nœud, ni dispersée). Le délai borne cette fenêtre.
> - **Ordre de suppression.** La nouvelle chaîne est envoyée en entier (§3.12.2 : tous les `write_block` avant l'`update_entry`), et l'ancienne n'est tombstonée (§4.3) qu'une fois la nouvelle entièrement confirmée par le Nœud : jamais avant, sinon une interruption laisserait le fichier sans version valide.
> - **Exclusions.** Cette règle ne concerne pas les lectures ; elle s'applique de la même façon à la création d'un fichier neuf.

---

## 9. §3.13 — Structure du système de fichiers

### 9.1 Remplacer le paragraphe « Immuabilité & modification » par

> **Immuabilité & modification.** Une chaîne de blocs, une fois écrite, n'est pas modifiée en place : l'adressage par contenu (`next_hash` = hash du bloc suivant) rendrait toute édition en milieu de chaîne invalidante en cascade. Modifier un fichier signifie le **réémettre intégralement** : nouveau `encryption_salt`, nouvelle chaîne de blocs (chiffrée du dernier bloc vers le premier, §3.8), nouveau `first_block_hash`, mise à jour de l'entrée de répertoire parente et donc de tous les blocs de répertoire jusqu'à `fs_root_hash`, en cascade et copy-on-write (§3.7). Chaque répertoire réémis reçoit lui aussi un `encryption_salt` neuf ; celui du répertoire racine est porté par le `UserEntryPlaintext` (§3.9) et mis à jour avec `fs_root_hash`. Les blocs de l'ancienne version deviennent orphelins et sont supprimés par tombstone bilatéral (§4.3) une fois la nouvelle version entièrement confirmée.

### 9.2 Remplacer la définition de `encryption_salt` dans la liste des champs de `DirectoryEntry`

> `encryption_salt` (16 octets d'un CSPRNG, neuf à chaque création ou réémission, jamais réutilisé ; dérive `K_block` avec `master_key[version]` et l'index du bloc, §3.8)

### 9.3 Compléments

- **Bloc fichier** : un `FileBlock` contient au plus `FILE_BLOCK_DATA_BYTES` octets de `data` (§3.8, format de bloc) ; le dernier bloc est complété par padding à zéro ; `size_bytes` fait foi.
- **Capacité d'un `DirectoryBlock`** : l'en-tête, le nonce et le tag du format de bloc (§3.8) réduisent d'un peu plus de 30 octets la place utile ; la valeur « ≤ 300 entrées » est à re-mesurer par un test.
- **Adressage** : inchangé. Le `block_hash` reste le hash du bloc chiffré complet de 65 536 octets.

---

## 10. §5.2 — `migration_pointer`

### 10.1 Remplacer le point 2 et compléter le point 3 de « Mécanisme proposé » par

> 2. **Publication du pointeur.** En cas de compromission de `priv_node` (mais pas de la seed), l'opérateur signe avec `priv_node_recovery` une `SignedMigrationPointer` (§3.11) portant `{old_node_id, new_node_id, seq, timestamp}` et la publie dans le champ `migration_pointer` de l'entrée DHT **de l'ancien** `node_id`.
>    - **Signature.** Ed25519 par `priv_node_recovery` sur `"s3m/migration-pointer/v1" || payload` (séparation de contexte : cette signature ne peut pas être confondue avec une autre signature de la même clé). ⚠ Libellé proposé.
>    - **Vérification.** Par tout pair, via le `pub_node_recovery` déjà publié dans l'entrée Node (§3.9), sans dépendre de la clé compromise. `old_node_id` doit être celui de l'entrée qui porte le pointeur.
>    - **Séquence et rejeu.** `seq` est monotone (premier pointeur : 1). Les pairs rejettent un pointeur dont `seq` est inférieur ou égal à celui déjà publié, ce qui empêche le rejeu d'un ancien pointeur et départage deux pointeurs concurrents.
> 3. **Côté Connecteur.** Lors de la résolution périodique de son Node (ou dès l'échec d'une opération), le Connecteur vérifie la présence d'un `migration_pointer` valide sur l'entrée de son `node_id` connu. Avant de le suivre, il vérifie que **l'entrée Node de `new_node_id` existe et est valide** (preuve VDF vérifiée, signature valide) : un pointeur vers une identité inexistante ou non vérifiable est ignoré. Le suivi automatique se limite à **un seul saut** : si l'entrée de `new_node_id` porte elle-même un `migration_pointer`, le Connecteur ne le suit pas automatiquement et demande une confirmation explicite à l'utilisateur. Un suivi valide déclenche la réattache, selon le même flux que la migration volontaire (§3.7.1).

### 10.2 Autres corrections

- Point 5 (« Limite fondamentale ») : inchangé. La limite d'un seul saut automatique réduit toutefois l'impact d'une redirection en chaîne par un attaquant qui aurait obtenu la seed.
- Point 6 (« Bascule de l'entrée DHT ») : la suppression explicite de l'ancienne entrée Node par `priv_node_recovery` est conservée ; elle concerne l'entrée Node, pas l'`EmergencyManifest`.

---

## 11. §7.3 — Packaging & interface

### 11.1 Remplacer le paragraphe « Déploiement du Connecteur »

> - **Déploiement du Connecteur** : **binaire Rust natif**, indépendant du Nœud (peut tourner sur une machine distincte). Le moteur (cryptographie, système de fichiers, DHT) est entièrement en Rust. **TypeScript ne concerne que l'interface** : le dashboard est un ensemble de fichiers web statiques, **servis par le binaire lui-même**. Aucun runtime JavaScript n'est requis à l'exécution. Le lecteur monté (§3.12) nécessite WinFsp ou FUSE.

### 11.2 Nouveau paragraphe : « API locale du Connecteur »

> L'interface dialogue avec le moteur par une **API locale** (HTTP et WebSocket) :
> - **Liaison** : uniquement `127.0.0.1`, sur un port connu du processus.
> - **Jeton** : un secret aléatoire propre à **chaque démarrage** (⚠ 256 bits recommandés), jamais écrit dans l'URL de requête, transmis dans l'en-tête `Authorization: Bearer`. Comparaison à temps constant.
> - **Remise du jeton au dashboard** : à l'ouverture du navigateur, le jeton est placé dans le **fragment d'URL** (`#…`), qui n'est jamais envoyé au serveur, ni journalisé, ni transmis dans `Referer`. La page le garde en mémoire et le retire de la barre d'adresse.
> - **`Origin`** : toute requête qui en porte un est rejetée si elle ne correspond pas exactement à l'origine du dashboard servi par le binaire. Aucun en-tête CORS permissif.
> - **`Host`** : limité à l'adresse et au port effectivement liés (protection contre le rebond DNS).
> - ⚠ **WebSocket** : les navigateurs ne permettent pas d'ajouter un en-tête `Authorization` à l'ouverture d'un WebSocket ; le jeton est envoyé dans le premier message, la connexion étant fermée sans lui. L'`Origin` et le `Host` sont vérifiés dès la poignée de main.
> - Cette API ne sert **pas** les fichiers de l'utilisateur : l'accès aux données passe uniquement par le lecteur monté (§3.12).

### 11.3 Autres corrections

- §7.3, dashboard Connecteur : ajouter l'état de l'**espace de travail** (§3.12.5), les paramètres du délai de synchronisation différée, et l'indicateur de synchronisations en attente.
- ⚠ Dashboard Nœud : la même démarche (jeton, `Origin`, `Host`) est recommandée, mais n'a pas été décidée.

---

## 12. Points ouverts découverts à la rédaction (❓)

1. **`K_dispersal_block` est circulaire pour la même raison que `K_block`.** La V2 définit `K_dispersal_block = KDF(K_dispersal_content, block_hash)` pour chiffrer les blocs internes de l'arbre d'index (§3.6, §3.8). Ces blocs sont adressés par le hash de leur contenu chiffré : le `block_hash` ne peut pas servir à les chiffrer. La même correction que pour `K_block` s'impose (dérivation par position dans l'arbre et par sel de version du manifeste) mais n'a **pas été décidée** ; la forme exacte (niveau et rang de l'`IndexNode`, sel porté par le parent) est à arrêter avant de modifier le §3.6 et le §3.8.
2. **Identité VDF d'une entrée User.** Le §2.1 exige une preuve VDF pour toute identité Node ou User, jointe sous la forme `(pub_key, y, π)`. Mais le §3.9 interdit de publier `pub_user` ; seule `sig_pub_user` apparaît. La preuve VDF d'une entrée User doit donc porter sur `sig_pub_user` marquée (`0x00 || sig_pub_user`), ce qui lie une preuve à chaque emplacement de publication ; ou sur une autre clé. À trancher.
3. **Séparation de contexte des signatures.** Seul le `migration_pointer` signe sur un libellé de contexte. Une règle uniforme (signer `libellé_du_type || payload` pour toutes les enveloppes) est recommandée mais n'a pas été décidée.
4. **Neutralisation d'un `EmergencyManifest` réconcilié.** Sans suppression, une entrée réconciliée reste découvrable 180 jours. Une option consiste à la remplacer, après réconciliation, par une version vide avec `seq + 1` : ce n'est pas une suppression, mais cela demande une règle supplémentaire. Non décidé ; la réconciliation idempotente (§7.2) suffit en attendant.
5. **Détails de dérivation de `Δ`** (expansion de `SHA-256` jusqu'à λ bits, parcours des candidats) : définis dans `vdf-identity.md`, non revus ici. À aligner une fois les mesures par phase disponibles.

---

## 13. Précisions ajoutées à la rédaction, à confirmer (⚠)

| Élément | Valeur proposée |
|---|---|
| Préfixe de protocole KDF | `"s3m/kdf/v1"` |
| Largeur du préfixe de longueur `L(x)` | 4 octets big-endian |
| Label de `K_attach` | `"attach"` (absent de la V2) |
| AAD d'un bloc de données | en-tête de version de 2 octets |
| AAD des blobs DHT | libellé du type d'entrée + `schema_version` (u16 big-endian) |
| Libellé de signature du `migration_pointer` | `"s3m/migration-pointer/v1"` |
| Ancrage du lissage | instants Unix `t ≡ offset_s (mod 2 592 000)` |
| Taille du jeton d'API locale | 256 bits |
| Jeton WebSocket | premier message |
| `file_identifier` FlatBuffers | un par type d'entrée |

---

## 14. Impact sur le plan d'implémentation

Ordre de réalisation recommandé :

1. **Migration `impl/connector`** : commit d'archivage (fichiers non suivis inclus), puis commit de suppression, limités à ce chemin. Critères : liste archivée = liste supprimée ; tests `impl/core` et `impl/node` verts ; aucune référence résiduelle au moteur TypeScript hors documentation.
2. **`network.vdf-verifier-pure`** (rouvert) : instrumentation par phases à `T=100`, fixtures générées avec `chiavdf` (MSVC, WSL ou Linux) et commitées, test MPIR en direct optionnel sous la feature `vdf`. Clôture sur quatre critères : natif, accord MPIR, rejets, traçabilité des fixtures. Cible `wasm32` : simple vérification de compilation non bloquante ; harnais WASM supprimé.
3. **Nouveau crate `impl/protocol`** (dépend de `impl/core`) : enveloppes, schémas, TTL, lissage, tags de clé, `migration_pointer`. L'enveloppe déjà écrite dans `impl/node` y est déplacée ; les 16 tests Node sont rejoués. Compléter `impl/TECH_STACK.md`.
4. **`impl/core`** : tâche distincte pour `sig_priv_user` et la convention HKDF (§3.1), avec vecteurs fixes, **avant** la tâche des signatures DHT.
5. **Rejeu des tests Node** avec le vrai vérificateur, puis nouvelle tâche Rust du moteur du Connecteur (DHT, séquences, `EmergencyManifest`).
6. **Clôture de `network.dht-directory`**, après les points ❓ 1 et 2 de §12.
7. **Lecteur monté** : trait de système de fichiers, backend WinFsp, cache d'écriture et synchronisation différée (§3.12.5).

**Vecteurs de test à prévoir**

- Tags de clé : rejet des tags 1, 2, 255 et d'un tag incohérent entre identité et enveloppe.
- Séquences : rejet d'un `seq` non croissant (`EmergencyEntry`, `migration_pointer`) ; deux écritures concurrentes avec la même séquence.
- TTL : constantes exactes en secondes (15 552 000 ; 31 536 000 ; 315 360 000 ; 2 592 000).
- Lissage : `offset_s` pour des identifiants fixes.
- Signatures : vérification sur les octets exacts du payload ; rejet d'un payload réserialisé différemment.
- `K_block` : indépendance vis-à-vis du `block_hash`, unicité par sel et par index, rejet d'une réutilisation de sel.
- Format de bloc : taille exacte de 65 536 octets, mesure de `FILE_BLOCK_DATA_BYTES`.
- Migration : un seul saut automatique, rejet d'un pointeur vers une entrée Node invalide.
