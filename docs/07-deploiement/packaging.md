---
id: deploiement.packaging
kind: narrative
title: "Packaging & Interface (Dashboards)"
section: "§7.3"
status: draft
verified_by: []
---

# Packaging & Interface

Deux applications Web locales distinctes (`http://127.0.0.1:<port>`) — l'une
pour le **Nœud**, l'autre pour le **Connecteur**. Chacune est un ensemble de
fichiers web statiques **servis par le binaire lui-même**, qui dialogue avec
le moteur par l'[API locale](#api-locale) ci-dessous.

## Dashboard Nœud

Volumes et quotas ([`node.NodeConfig`](../02-schemas/node/NodeConfig.md)),
utilisateurs rattachés
([`node.AttachedUser`](../02-schemas/node/AttachedUser.md)), état des
partenaires ([`node.PartnerAccount`](../02-schemas/node/PartnerAccount.md),
dernière PoS réussie, purge à venir), liste noire
([`securite.blacklist-fraude`](../05-securite/blacklist-fraude.md)), taux
de republication DHT
([`network.dht-directory`](../01-network-dht/dht-directory.md)), alertes de
scrubbing/auto-réparation
([`securite.integrite-autoreparation`](../05-securite/integrite-autoreparation.md)),
espace de secours occupé/réservé pour tiers en détresse
([`protocols.espace-secours`](../04-protocols/espace-secours.md)).

### Liste des partenaires et carte {: #carte }

Ajout du 2026-11-20 ([`protocols.partenariat-automatique`](../04-protocols/partenariat-automatique.md)) :

- liste des partenaires triable : score et composantes, état (actif, en
  retrait, terminé), fragments confiés et reçus, solde accordé, dernier
  challenge réussi, latence, pays ;
- **carte du monde** plein écran : partenaires, Nœuds non partenaires
  (candidats découverts), Nœuds en liste noire, Utilisateurs rattachés —
  chaque type affichable ou masquable ; points proches regroupés en bulles
  portant leur nombre, dégroupées au zoom ; détail au clic ;
- fond de carte embarqué (Natural Earth, domaine public) : aucune tuile ni
  service en ligne ;
- localisation par adresse IP avec une base locale au format MMDB (DB-IP
  « City Lite », CC BY 4.0, attribution affichée), téléchargée à la demande
  de l'opérateur (`s3m-node geoip-update`) ; adresse publiée dans
  l'entrée DHT pour les Nœuds, adresse de la dernière connexion pour les
  Utilisateurs (enregistrement désactivable) ; adresses privées ou
  inconnues comptées « non localisées ».

## Dashboard Connecteur

Nœud rattaché et son état de joignabilité, palier d'alerte de migration en
cours (ancienneté de `inactivity_detected_at`), état de la
[`protocols.write-queue`](../04-protocols/write-queue.md) (mutations en
attente, taille, dernière synchronisation, entrées rejetées pour
dépassement de quota — [`protocols.quota-sync`](../04-protocols/quota-sync.md)),
état de l'écriture d'urgence
([`protocols.espace-secours`](../04-protocols/espace-secours.md) —
partenaires utilisés, estimation du quota consommé par les autres
Connecteurs), historique des incidents d'intégrité
([`protocols.integrite-lecture`](../04-protocols/integrite-lecture.md)),
configuration de `Q_max` (4 GiO par défaut) et de l'intervalle de
surveillance (5 minutes par défaut). État de l'**espace de travail** de
l'[écriture différée](../04-protocols/ecriture-differee.md) (occupation,
réserve `workspace_reserve_bytes`), paramètres du délai de synchronisation
différée, indicateur des synchronisations en attente et action
« synchroniser maintenant ».

## Déploiement

- **Nœud** : image conteneurisée officielle Docker (et binaire autonome),
  NAS/serveurs domestiques/Raspberry Pi.
- **Connecteur** : **binaire Rust natif**, indépendant du Nœud (peut
  tourner sur une machine distincte). Le moteur (cryptographie, système de
  fichiers, DHT) est entièrement en Rust. **TypeScript ne concerne que
  l'interface** : le dashboard est un ensemble de fichiers statiques servis
  par le binaire ; aucun runtime JavaScript n'est requis à l'exécution. Le
  lecteur monté ([`protocols.acces-applicatif`](../04-protocols/acces-applicatif.md))
  nécessite WinFsp ou FUSE.

### Application de la barre des tâches (Connecteur, Windows) {: #barre-des-taches }

Ajout du 2026-11-20. Le Connecteur s'utilise comme les applications de
synchronisation courantes :

- **Application de session** `S3m.exe` (pas un service Windows : un
  service tourne hors de la session et ne pourrait ni afficher d'icône ni
  présenter le lecteur monté à l'utilisateur). Sans fenêtre de console, une
  seule instance par utilisateur, lancée à l'ouverture de session si
  l'option « Démarrer avec Windows » est cochée (clé `Run` du profil).
  `s3m-connector.exe` reste disponible en ligne de commande.
- **Emplacement** : `%APPDATA%\S3m` — configuration, phrase de
  récupération, journaux (`logs\`) et données de travail.
- **Icône** dont la couleur suit l'état : à jour, synchronisation en cours,
  synchronisation suspendue, Nœud injoignable, erreur. Infobulle avec l'état
  en clair.
- **Menu** : état ; ouvrir le lecteur ; ouvrir le tableau de bord ;
  synchroniser maintenant ; suspendre / reprendre la synchronisation (les
  modifications restent journalisées localement) ; démarrer avec Windows ;
  ouvrir les journaux ; quitter (démonte le lecteur).
- **Notifications Windows** pour les événements importants : conflit de
  synchronisation, Nœud injoignable depuis plus de 10 minutes puis de
  nouveau joignable, rattachement automatique accepté ou refusé, erreur de
  synchronisation persistante.
- **Assistant de premier lancement** (aucune configuration) : création de
  la phrase de récupération (affichée une fois, à recopier), recherche des
  Nœuds du réseau local
  ([`network.bootstrap`](../01-network-dht/bootstrap.md#reseau-local)), choix
  du Nœud ou saisie manuelle de son adresse, puis démarrage normal ; le
  rattachement est demandé automatiquement
  ([`protocols.partenariat-automatique`](../04-protocols/partenariat-automatique.md)).

## API locale {: #api-locale }

Chaque dashboard dialogue avec son moteur par une **API locale** (HTTP et
WebSocket). Les mêmes protections s'appliquent au Nœud et au Connecteur
(arbitrage du 2026-11-19) :

- **Liaison** : uniquement `127.0.0.1`, sur un port connu du processus.
- **Jeton** : un secret aléatoire de **256 bits**, propre à **chaque
  démarrage**, jamais écrit dans l'URL de requête, transmis dans l'en-tête
  `Authorization: Bearer`. Comparaison à temps constant.
- **Remise du jeton au dashboard** : à l'ouverture du navigateur, le jeton
  est placé dans le **fragment d'URL** (`#…`), qui n'est jamais envoyé au
  serveur, ni journalisé, ni transmis dans `Referer`. La page le garde en
  mémoire et le retire de la barre d'adresse.
- **`Origin`** : toute requête qui en porte un est rejetée si elle ne
  correspond pas exactement à l'origine du dashboard servi par le binaire.
  Aucun en-tête CORS permissif.
- **`Host`** : limité à l'adresse et au port effectivement liés (protection
  contre le rebond DNS).
- **WebSocket** : les navigateurs ne permettent pas d'ajouter un en-tête
  `Authorization` à l'ouverture d'un WebSocket ; le jeton est envoyé dans le
  **premier message**, la connexion étant fermée sans lui. `Origin` et
  `Host` sont vérifiés dès la poignée de main.
- Côté Connecteur, cette API ne sert **pas** les fichiers de l'utilisateur :
  l'accès aux données passe uniquement par le lecteur monté.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
