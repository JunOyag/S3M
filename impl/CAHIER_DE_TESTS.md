# Cahier de tests — fiabilité de S3m

Version du 2026-11-25. Objectif : démontrer la fiabilité du système sur un
réseau réel (30 Nœuds locaux au minimum, puis plusieurs machines et sites)
et faire apparaître les améliorations importantes ou critiques à cadrer.

## Conventions

- **Priorité** : P0 critique (perte ou fuite de données, compromission) ·
  P1 majeure (indisponibilité durable, réparation manuelle) · P2 notable
  (dégradation, confort).
- **Couverture actuelle** : ✅ test automatisé existant · 🟡 partielle
  (logique testée, jamais en conditions réelles) · ❌ aucune · ⚠ lacune
  connue : le résultat attendu n'est pas atteint aujourd'hui (amélioration
  à cadrer, voir la synthèse finale).
- **Constat** à consigner pour chaque essai : date, version, topologie,
  durée, résultat (conforme / non conforme), journaux des Nœuds et de S3m,
  captures du tableau de bord.
- Sauf mention contraire, chaque essai commence sur un réseau stable :
  dispersion à jour (« Stockage et protection »), annuaire persisté depuis
  au moins 10 minutes, Connecteurs « À jour ».
- Les essais destructifs se font sur les Nœuds de test (`D:\nodes\…`), jamais
  sur un Nœud portant des données réelles.

---

## 1. Volumes (stockage physique d'un Nœud)

| ID | Priorité | Scénario | Résultat attendu | Couverture |
|---|---|---|---|---|
| VOL-01 | P0 | Supprimer le dossier d'un volume pendant que le Nœud tourne | Maintenance sous 30 s, Utilisateurs prévenus, blocs reconstruits depuis la parité, fin de maintenance annoncée, aucune donnée perdue si tout était dispersé | ✅ `maintenance::a_deleted_volume_is_rebuilt_from_the_network` · 🟡 réel |
| VOL-02 | P0 | Même suppression, Nœud arrêté, puis redémarrage | Le Nœud démarre, détecte la perte, même suite que VOL-01 | ✅ `disk_faults::a_deleted_volume_folder_does_not_prevent_startup` · 🟡 réel |
| VOL-03 | P0 | « Ransomware » côté Nœud : chiffrer/écraser le contenu de tous les fichiers conteneurs (tailles inchangées) | Scrubbing : blocs altérés détectés, alerte « Blocs altérés / remplacer le disque », reconstruction depuis la parité, lectures du Connecteur toujours justes (hash vérifié) | ⚠ détection seulement au scrubbing quotidien, pas de passage en maintenance sur altération massive |
| VOL-04 | P0 | Altérer quelques octets d'un bloc précis | Le Connecteur rejette le bloc (hash), lit la version reconstruite, signale l'incident ; le Nœud répare sa copie | ✅ `integrity::*`, `self_repair::*` · 🟡 réel |
| VOL-05 | P0 | Perte simultanée du volume et de plus de `coef × k` partenaires d'un même stripe | Blocs déclarés irrécupérables, nombre exact annoncé aux Utilisateurs ; aucun bloc faux servi | ❌ |
| VOL-06 | P1 | Débrancher le disque d'un volume (ou changer sa lettre) | Alerte « Volume introuvable », rien n'est oublié ni reconstruit, aucune allocation sur ce volume ; rebrancher efface l'alerte | ✅ `disk_faults::an_unplugged_disk_is_reported_without_forgetting_its_blocks` · 🟡 réel |
| VOL-07 | P1 | Disque plein (remplir le disque hors S3m) | Alerte « Disque plein », refus propres des écritures, aucune corruption de la base | ❌ |
| VOL-08 | P1 | Droits retirés sur le dossier du volume | Alerte « Accès refusé » avec conduite à tenir | ❌ |
| VOL-09 | P1 | Supprimer ou corrompre la base SQLite (`store.sqlite`) en gardant les conteneurs | Démarrage refusé avec message clair, ou reconstruction de l'index depuis les conteneurs ; jamais de perte silencieuse | ⚠ aucun mécanisme de reconstruction de la base |
| VOL-10 | P1 | Coupure de courant pendant des écritures (tuer le processus en boucle pendant un envoi massif) | Base et conteneurs cohérents au redémarrage, blocs en attente repris (`reconcile`) | 🟡 |
| VOL-11 | P1 | Erreurs de lecture intermittentes (disque défaillant simulé) | Alerte « Erreurs de lecture » avec compteur, lectures servies par reconstruction | ❌ (difficile à simuler : prévoir un volume sur disque virtuel défaillant) |
| VOL-12 | P2 | Ajout, vidage, retrait, déclaration « perdu » d'un volume en charge | Blocs déplacés ou reconstruits, aucune interruption de service | ✅ `volumes::*` · 🟡 réel |
| VOL-13 | P2 | Import d'un ancien volume (disque déplacé) | Blocs reconnus réintégrés, inconnus ignorés | ✅ · 🟡 réel |

## 2. Nœuds

### 2.1 Pannes et destruction

| ID | Priorité | Scénario | Résultat attendu | Couverture |
|---|---|---|---|---|
| NOD-01 | P0 | Destruction complète d'un Nœud (dossier effacé), recréation avec sa seed | Sauvegarde retrouvée dans l'annuaire, Utilisateurs et partenaires repris, fichiers reconstruits, Connecteurs revenus sans action | 🟡 échoué le 2026-11-24 (annuaire perdu), corrigé depuis : à rejouer |
| NOD-02 | P0 | Même destruction **et** redémarrage simultané de tout le réseau | Annuaire rechargé depuis le disque de chaque Nœud ; NOD-01 réussit | ✅ `dht_records::*` · 🟡 réel |
| NOD-03 | P0 | Destruction d'un Nœud sans recréation | Ses Utilisateurs basculent en écriture d'urgence et lecture de secours ; les partenaires replacent leurs fragments ; purge des fragments du Nœud disparu après 6 mois | 🟡 |
| NOD-04 | P1 | Nœud arrêté 7 mois puis redémarré | Aucun Utilisateur supprimé (temps d'arrêt rendu), partenariats repris ou remplacés | ✅ `inactivity::a_stopped_node_gives_its_downtime_back` · ❌ réel |
| NOD-05 | P1 | Coupure réseau d'un Nœud 1 h, 24 h, 8 jours | Connecteurs en mode hors ligne puis resynchronisés ; partenaires : manquements comptés sans exclusion abusive | 🟡 |
| NOD-06 | P1 | Changement d'adresse IP / NAT du Nœud | Connecteurs le retrouvent via l'annuaire ou le réseau local | ✅ `node_moved`, `nat` |
| NOD-07 | P2 | Horloge du Nœud décalée (±1 h, +1 an) | Aucune suppression ni expiration en masse ; signatures et avis rejoués refusés | ⚠ une horloge avancée d'un an supprimerait les Utilisateurs inactifs et rendrait l'annuaire incohérent |

### 2.2 Compromission et implémentations pirates

| ID | Priorité | Scénario | Résultat attendu | Couverture |
|---|---|---|---|---|
| NOD-10 | P0 | Partenaire qui jette les fragments reçus et répond « introuvable » | Manquements, retrait après 3, fragments replacés | ✅ `upkeep::*`, `exchange` |
| NOD-11 | P0 | Partenaire qui renvoie des données fausses aux contrôles (PoS) | Fraude détectée, liste noire, réparation immédiate | ✅ |
| NOD-12 | P0 | Partenaire qui garde seulement les hash et recalcule les réponses | Impossible : le contrôle porte sur un nonce frais ; fraude détectée | ✅ |
| NOD-13 | P0 | Nœud principal malveillant servant une **ancienne** racine (retour arrière) | Risque assumé (§3.12) : documenter ce que voit l'Utilisateur ; le Connecteur qui connaît une racine plus récente doit le signaler | ⚠ aucune détection côté Connecteur |
| NOD-14 | P0 | Nœud principal qui lit les données de ses Utilisateurs | Impossible : blocs chiffrés de bout en bout, descripteur de racine illisible | ✅ (cryptographie) · ❌ audit externe |
| NOD-15 | P1 | Nœud Sybil : 20 identités de partenaires sur une même machine | Limite par sous-réseau (si activée), coût VDF par identité | ✅ `partnering` (sous-réseau) |
| NOD-16 | P1 | Partenaire qui promet de l'espace puis refuse (quota négocié non tenu) | Manquements, confiance réinitialisée, remplissage révélant la tricherie | ✅ |
| NOD-17 | P1 | Partenaire qui s'annonce « en maintenance » en permanence pour échapper aux manquements | Doit finir par être traité comme défaillant | ⚠ aucune limite de durée ou de fréquence des maintenances déclarées |
| NOD-18 | P1 | Virus sur la machine d'un Nœud : vol de `node.seed` | Usurpation possible ; alerte de compromission et migration vers un Nœud de remplacement | 🟡 `canal-noeud` (alerte) |
| NOD-19 | P2 | Messages malformés / géants / en rafale (fuzzing du protocole) | Refus propres, pas de panne ni de fuite mémoire | ❌ |

## 3. Redondance et réparation

| ID | Priorité | Scénario | Résultat attendu | Couverture |
|---|---|---|---|---|
| RED-01 | P0 | Arrêt simultané de `coef × k` partenaires d'un stripe (limite tolérée) | Lecture et reconstruction toujours possibles | ✅ `erasure` · 🟡 réel |
| RED-02 | P0 | Un partenaire de plus que la limite | Blocs signalés irrécupérables, sans donnée fausse | ❌ |
| RED-03 | P0 | Délai entre réception d'un bloc et sa dispersion (bloc seul chez le Nœud) | Mesurer la fenêtre ; une perte du Nœud pendant cette fenêtre perd le bloc sauf si le Connecteur en a une copie | ⚠ aucun renvoi automatique par le Connecteur des blocs non dispersés perdus |
| RED-04 | P1 | Disparition lente de partenaires (10 % par jour) | Replacement continu, redondance maintenue | 🟡 |
| RED-05 | P1 | Réseau trop petit (moins de `k × (1 + coef)` partenaires joignables) | Confirmations insuffisantes signalées clairement, aucune perte | 🟡 |
| RED-06 | P2 | Mesure : délai de dispersion d'un fichier de 1 Gio, de 10 000 petits fichiers | Valeurs de référence consignées | ❌ |

## 4. Annuaire (DHT)

| ID | Priorité | Scénario | Résultat attendu | Couverture |
|---|---|---|---|---|
| DHT-01 | P0 | Redémarrage de tous les Nœuds | Entrées rechargées depuis le disque, aucune perte | ✅ `dht_records` |
| DHT-02 | P0 | Entrée falsifiée ou rejouée (mauvaise signature, ancienne version) | Rejetée à la lecture | ✅ |
| DHT-03 | P1 | Entrée User absente (> 6 mois) | Appareil neuf : Nœud retrouvé par identité ou empreinte, sel et racine rendus par le Nœud | ✅ unitaires · ❌ bout en bout |
| DHT-04 | P1 | Éclipse : un attaquant contrôle tous les voisins d'une clé | Lecture échoue ou rend une entrée signée valide ; jamais une entrée forgée | ❌ |
| DHT-05 | P1 | Partition réseau (deux moitiés pendant 1 h) puis réunion | Convergence des entrées, aucune incohérence durable | ❌ |
| DHT-06 | P2 | Aucun Nœud sur le réseau local, aucun pair connu | Message clair dans l'assistant ; saisie d'une adresse permet d'entrer | 🟡 |

## 5. Connecteur et données

| ID | Priorité | Scénario | Résultat attendu | Couverture |
|---|---|---|---|---|
| CON-01 | P0 | Nœud injoignable pendant des écritures | Modifications gardées localement, écriture d'urgence chez les partenaires de secours, renvoi au retour du Nœud | ✅ `emergency`, `write_queue` · 🟡 réel |
| CON-02 | P0 | Ransomware côté utilisateur : chiffrer tout le dossier synchronisé | Les versions chiffrées sont envoyées ; il doit être possible de **revenir à une version antérieure** | ⚠ aucune restauration à une date ; « Libérer les anciennes versions » détruit cet historique |
| CON-03 | P0 | Suppression accidentelle d'un dossier entier par l'utilisateur | Récupération possible pendant un délai (corbeille, versions) | ⚠ aucune corbeille |
| CON-04 | P0 | Lecture de secours, Nœud arrêté | Fichiers lisibles depuis la parité des partenaires | ✅ |
| CON-05 | P1 | Arrêt brutal du PC pendant un envoi | File d'écriture rejouée, aucun fichier tronqué côté Nœud | ✅ `write_queue` · 🟡 réel |
| CON-06 | P1 | Nœud recréé vide (sans restauration) | Message « fichiers introuvables chez votre Nœud », racine non transmise | ✅ `files_missing` |
| CON-07 | P1 | Disque du PC plein, dossier synchronisé déplacé ou supprimé | Erreur claire, aucune propagation de suppression non voulue | ❌ |
| CON-08 | P2 | Libération d'espace puis réouverture hors ligne d'un fichier libéré | Message clair ; lecture de secours si possible | 🟡 |

## 6. Accès concurrents

| ID | Priorité | Scénario | Résultat attendu | Couverture |
|---|---|---|---|---|
| CNC-01 | P0 | Deux appareils de la même identité modifient le même fichier en même temps | Conflit détecté, la plus récente gagne, l'autre gardée en « (conflit …) », rien de perdu | ✅ `drive` (rebase) · 🟡 réel |
| CNC-02 | P0 | Un appareil supprime un dossier que l'autre modifie | Les modifications ne sont pas perdues | ✅ · 🟡 réel |
| CNC-03 | P1 | Appareil hors ligne 2 semaines avec de nombreuses modifications, puis retour | Fusion complète, copies de conflit nommées | 🟡 |
| CNC-04 | P1 | Écritures d'urgence de deux appareils pendant la même panne du Nœud | Réconciliation sans perte au retour du Nœud | 🟡 |
| CNC-05 | P2 | Explorateur web et dossier synchronisé modifiés simultanément | Même comportement que CNC-01 | ❌ |

## 7. Partages

| ID | Priorité | Scénario | Résultat attendu | Couverture |
|---|---|---|---|---|
| PAR-01 | P0 | Retrait d'un partage | Le destinataire ne lit plus rien, immédiatement | ✅ `shares` |
| PAR-02 | P0 | Destinataire qui tente d'écrire ou de lire hors du dossier partagé | Refusé | ✅ |
| PAR-03 | P1 | Partage expiré, débit de lecture excessif | Refus, limitation | ✅ |
| PAR-04 | P1 | Lien de partage transmis à un tiers | Documenter la portée (le porteur lit) | 🟡 |
| PAR-05 | P2 | Propriétaire supprimé pour inactivité | Partages caducs, message clair au destinataire | ❌ |

## 8. Identités utilisateur

| ID | Priorité | Scénario | Résultat attendu | Couverture |
|---|---|---|---|---|
| IDE-01 | P0 | Appareil neuf, phrase de récupération seule, entrée User présente | Nœud trouvé automatiquement, fichiers lisibles | 🟡 |
| IDE-02 | P0 | Appareil neuf, phrase seule, entrée User expirée | Nœud saisi, sel et racine rendus par le Nœud, fichiers lisibles | ✅ unitaires · ❌ bout en bout |
| IDE-03 | P0 | Vol de la phrase de récupération | Le voleur lit tout ; il faut pouvoir **changer d'identité** en conservant ses fichiers | ⚠ aucune rotation d'identité utilisateur |
| IDE-04 | P0 | Perte de la phrase et de tous les appareils | Données irrécupérables (assumé) : vérifier que l'utilisateur en est clairement prévenu à la création | 🟡 |
| IDE-05 | P1 | Utilisateur inactif au-delà de sa durée | Supprimé avec ses fragments ; éternel jamais supprimé | ✅ `inactivity::*` · ❌ réel |
| IDE-06 | P1 | Plusieurs identités sur un même PC, archivage, réactivation, suppression | Aucune fuite entre identités, lecteurs distincts | 🟡 |
| IDE-07 | P2 | Reprise d'une identité sur un Nœud qui l'a supprimée | Traitée comme nouvelle, message clair | ❌ |

## 9. Administration et exploitation

| ID | Priorité | Scénario | Résultat attendu | Couverture |
|---|---|---|---|---|
| ADM-01 | P0 | Accès au tableau de bord du Nœud depuis le réseau sans 2FA | Refusé | ✅ |
| ADM-02 | P1 | Mise à jour d'un Nœud sur 30 avec une version plus récente | Compatibilité des messages (champs ajoutés ignorés par les anciens) | 🟡 |
| ADM-03 | P1 | Alerte disque, maintenance, messages : l'opérateur absent du tableau de bord les reçoit-il ? | Notification hors tableau de bord (courriel, barre des tâches) | ⚠ alertes visibles seulement à l'ouverture du tableau de bord |
| ADM-04 | P2 | Montée en charge : 100 Utilisateurs, 1 To par Nœud | Temps de cycle, mémoire, taille de l'annuaire consignés | ❌ |

---

## Synthèse : améliorations à cadrer

Classées par priorité, issues des lacunes ⚠ ci-dessus.

| Rang | Priorité | Amélioration | Essais |
|---|---|---|---|
| 1 | P0 | **Historique et retour arrière** : garder les racines passées pendant une durée (30 jours par exemple), corbeille, restauration d'un dossier à une date ; protéger cet historique de « Libérer les anciennes versions » | CON-02, CON-03 |
| 2 | P0 | **Rotation d'identité utilisateur** après vol de la phrase : nouvelle identité qui reprend les fichiers, ancienne révoquée | IDE-03 |
| 3 | P0 | **Renvoi des blocs non dispersés** : le Connecteur garde ses blocs jusqu'à confirmation de dispersion et les renvoie si le Nœud les a perdus | RED-03, VOL-05 |
| 4 | P0 | **Altération massive** : passer en maintenance quand le scrubbing ou les lectures trouvent beaucoup de blocs altérés (ransomware côté Nœud), relecture complète immédiate | VOL-03 |
| 5 | P1 | **Garde-fou d'horloge** : refuser les suppressions et expirations après un saut d'horloge anormal | NOD-07 |
| 6 | P1 | **Détection du retour arrière** de racine par le Connecteur | NOD-13 |
| 7 | P1 | **Limite des maintenances déclarées** par un partenaire (durée, fréquence) | NOD-17 |
| 8 | P1 | **Reconstruction de la base** du stockage depuis les conteneurs | VOL-09 |
| 9 | P1 | **Alertes hors tableau de bord** pour l'opérateur (notification, courriel) | ADM-03 |
| 10 | P2 | Fuzzing du protocole, essais de partition et d'éclipse de l'annuaire, mesures de performance | NOD-19, DHT-04, DHT-05, RED-06, ADM-04 |

## Mise en œuvre

- Les essais ✅ sont rejoués à chaque modification (`cargo test` dans
  `impl/core`, `impl/protocol`, `impl/node`, `impl/connector`).
- Les essais 🟡 et ❌ en conditions réelles s'automatisent en scénarios
  Docker Compose (`tests/integration/scenarios/`, un par identifiant), en
  commençant par les P0 : NOD-01, NOD-02, VOL-01, VOL-03, CON-01, CON-02,
  CNC-01, IDE-02.
- Une lacune ⚠ confirmée par un essai devient une entrée de
  `impl/SPEC_GAPS.md`, puis une fonctionnalité cadrée.

## Campagne du 2026-11-25 : améliorations réalisées et résultats

Les dix améliorations de la synthèse sont intégrées (spec, code, tests) :

| Rang | Amélioration | Couverture désormais | Essais |
|---|---|---|---|
| 1 | Historique des versions, restauration, purge, garde-fou rançongiciel | ✅ `history::*` | CON-02, CON-03 |
| 2 | Rotation d'identité, « Rechiffrer avec la nouvelle clé » | ✅ `rotation::*`, `exchange::rotation_*` | IDE-03 |
| 3 | Copie locale des blocs jusqu'à leur dispersion | ✅ `unsent::*` | RED-03, VOL-05 (partiel) |
| 4 | Altération massive → maintenance et relecture complète | ✅ `maintenance::a_burst_*` | VOL-03 |
| 5 | Garde-fou d'horloge | ✅ `clock_guard::*` | NOD-07 |
| 6 | Retour arrière : tout l'espace à une version ; ancienne version imposée refusée | ✅ `rollback::*` | NOD-13 |
| 7 | Maintenance déclarée : 24 h, une fois par semaine | ✅ `exchange::a_partner_maintenance_*` | NOD-17 |
| 8 | Reconstruction de la base du stockage | ✅ `disk_faults::a_lost_or_corrupted_*` | VOL-09 |
| 9 | Alertes hors tableau de bord (fenêtre, webhook, courriel) | ✅ `alerts::*` | ADM-03 |
| 10 | Fuzzing, partition de l'annuaire, mesures | ✅ voir ci-dessous | NOD-19, DHT-05, RED-06 |

### Fuzzing (NOD-19)

- `protocol/tests/fuzz.rs` : 20 000 messages aléatoires ou altérés, 20 000
  enveloppes d'annuaire ; `node/tests/fuzz_requests.rs` : requêtes aux
  champs aléatoires sous un identifiant valide.
- **Défaut trouvé et corrigé** : un message ou une enveloppe d'annuaire de
  moins de 8 octets faisait paniquer le décodeur FlatBuffers ; reçu d'un
  pair dans l'annuaire, il pouvait faire tomber la boucle réseau du Nœud.

### Partition de l'annuaire (DHT-05)

- `node/tests/partition.rs`, pile réseau de production : deux groupes
  isolés ne se voient pas ; un Nœud qui les relie rend l'entrée lisible
  partout, sans attendre de republication. ✅
- Éclipse (DHT-04) : non outillé ; l'intégrité reste garantie par la
  vérification des signatures (DHT-02).

### Mesures de référence (RED-06), `cargo run --release --example perf`

Machine de développement (Windows), 32 Mio, blocs de 64 Kio :

| Opération | Débit |
|---|---|
| Chiffrement des blocs (ChaCha20-Poly1305) | 959 Mio/s |
| Hachage SHA-256 | 1 693 Mio/s |
| Parité Reed-Solomon k=2, coef=2 | 862 Mio/s |
| Parité Reed-Solomon k=4, coef=3 | 323 Mio/s |
| **Écriture du stockage physique** | **6,6 Mio/s** |
| Relecture du stockage physique | 388 Mio/s |

### Nouvelles améliorations à cadrer

| Priorité | Constat | Piste |
|---|---|---|
| P1 | L'écriture sur le stockage physique plafonne à 6,6 Mio/s : chaque bloc est synchronisé sur le disque un par un (données, en-tête, journal SQLite) ; un envoi de 1 Gio prend environ 2 min 30 côté Nœud | Écritures groupées : un `sync` et une transaction par lot de blocs reçus, réponse `Stored` après le lot |
| P2 | Les scénarios Docker de `tests/integration/` sont des squelettes (pas de Dockerfile) | Images Nœud / Connecteur et scénarios NOD-01, VOL-01, CON-01 automatisés |
| P2 | Bloc non dispersé perdu alors que sa copie locale a été abandonnée (au-delà de Q_max) | Signaler l'abandon de copie à l'Utilisateur, ou ralentir l'envoi plutôt qu'abandonner |

## 10. Parcours débutant (mode simple)

À mener avec une personne qui découvre S3m, sans aide, en mode simple ;
noter les hésitations, les messages incompris et le temps passé.

| ID | Priorité | Scénario | Résultat attendu | Couverture |
|---|---|---|---|---|
| ERG-01 | P1 | Installer S3m, créer une identité, noter la phrase, voir « Tout est à jour » | Parcours compris sans aide en moins de 10 minutes ; l'attente de la preuve d'identité est expliquée | ❌ |
| ERG-02 | P1 | Retrouver un fichier supprimé par erreur hier | « Mes fichiers » → « Revenir en arrière » → restauration, sans aide | ❌ |
| ERG-03 | P1 | Rançongiciel simulé (fichiers chiffrés) : suspension, puis retour de tout l'espace à une date | La personne comprend l'alerte et ne reprend pas la synchronisation | ❌ |
| ERG-04 | P1 | Phrase compromise : changer d'identité, noter la nouvelle phrase, tout rechiffrer | Phrase notée, éléments 🔓 compris et rechiffrés | ❌ |
| ERG-05 | P2 | Opérateur : voyant rouge « Disques », remplacer le disque en suivant la marche à suivre | Aucune perte, aucune aide | ❌ |
| ERG-06 | P2 | Passer en mode expert puis revenir au mode simple | Choix retenu, aucun écran perdu | ✅ `daemon` (écrans et actions du mode simple) |
