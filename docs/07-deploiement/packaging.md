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

Au premier lancement, le dashboard propose **nouvelle identité** ou
**identité existante**, sous identité temporaire, et affiche le code
d'appairage ([`deploiement.appairage-admin`](appairage-admin.md)) ; il passe
ensuite au dashboard ci-dessous sans changer d'adresse ni de jeton. La
section « administration à distance » affiche à la demande le QR code 2FA et
permet de le régénérer.

**Ports du Nœud** : `listen` (par défaut `/ip4/0.0.0.0/tcp/4001`) porte toute
la pile réseau — DHT, échange de blocs, traversée de NAT — en TCP, et QUIC
sur le même numéro en UDP ; `admin_listen` (4003, TCP) porte le canal
d'administration. Les anciens réglages `dht_listen` / `blocks_listen`
restent lus s'ils figurent dans la configuration.

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
  retrait, terminé), fragments confiés et reçus, dernier
  challenge réussi, latence, pays ;
- **carte du monde** plein écran : partenaires, Nœuds non partenaires
  (candidats découverts), Nœuds en liste noire, Utilisateurs rattachés —
  chaque type affichable ou masquable ; points proches regroupés en bulles
  portant leur nombre, dégroupées au zoom ; détail au clic ;
- fond de carte embarqué (Natural Earth, domaine public) : aucune tuile ni
  service en ligne ;
- localisation par adresse IP avec une base locale au format MMDB (DB-IP
  « City Lite », CC BY 4.0, attribution affichée), téléchargée à la demande
  de l'opérateur (`s3m-node geoip-update`, ou bouton du dashboard :
  téléchargement en arrière-plan et rechargement sans redémarrage) ; si cette
  base n'est pas téléchargeable, **repli automatique sur le pays** d'après
  les données publiques des cinq registres Internet régionaux (fichier
  local `rir-country.bin`, point au centre approximatif du pays, source
  affichée) ; adresse publiée dans
  l'entrée DHT pour les Nœuds, adresse de la dernière connexion pour les
  Utilisateurs (enregistrement désactivable) ; une adresse privée (réseau
  local) est localisée par l'adresse publique de ce Nœud (`public_ip`,
  adresse externe confirmée, adresse de la box lue par UPnP même si
  l'ouverture de port est refusée, ou adresse vue par un pair distant) et marquée « réseau local » ;
  adresses inconnues, ou privées sans adresse publique connue, comptées
  « non localisées ».

### Configuration depuis le dashboard {: #configuration }

Ajout du 2026-11-20 : les réglages de `node.json` sont modifiables par
formulaires groupés (réseau, relais, partenaires, contrôles, vie privée),
pré-remplis avec les valeurs effectives. Seuls les champs modifiés sont
réécrits ; la configuration complète est validée avant une écriture
atomique. La politique d'acceptation des partenaires et l'enregistrement
des adresses des Utilisateurs s'appliquent immédiatement ; les autres
réglages au prochain redémarrage, que le dashboard signale. Identité,
répertoires, volumes et paramètres d'effacement (k, coef) ne sont pas
modifiables ainsi (risque de perte de données).

## Dashboards : écrans et menu {: #ecrans }

Ajout du 2026-11-20. Chaque dashboard est découpé en écrans reliés par un
menu (latéral, en haut sur petit écran). Le moteur décrit les écrans
(`pages` : sections et actions de chacun) et les indicateurs de la vue
d'ensemble (`résumé` : libellé, valeur, état ok / attention / problème,
écran de détail au clic) ; ce qu'aucun écran ne cite tombe dans le dernier
(« Diagnostic » ou « Paramètres »).

- **Nœud** : vue d'ensemble, utilisateurs, partenaires, carte du monde,
  volumes ([`protocols.gestion-volumes`](../04-protocols/gestion-volumes.md) :
  liste des actions appliquée d'un coup après confirmation), stockage et protection,
  réseau, administration à distance, configuration, diagnostic.
- **Connecteur** : vue d'ensemble, fichiers et synchronisation, mon Nœud,
  identité et sécurité, paramètres.

Les tailles s'affichent en unités lisibles, les instants en date locale ;
chaque tableau se trie par colonne, se pagine au-delà de 25 lignes et
s'exporte en CSV ; une action peut exiger une fenêtre de confirmation
(`confirmer`). L'écran Réseau du Nœud affiche le **taux de
republication DHT** : part des entrées qu'il gère (entrée Node,
DispersalManifest de chaque Utilisateur) republiées dans la période de
[`network.dht-directory`](../01-network-dht/dht-directory.md#expiration-et-republication)
(30 jours, tolérance d'un jour) ;
l'écran courant est conservé au rechargement, et `#token=…&page=<id>`
ouvre directement un écran.

## Dashboards : retours d'action {: #retours }

Le résultat de chaque action s'affiche dans un message éphémère (succès ou
erreur), le bouton étant désactivé pendant l'envoi ; les actions propres à
un élément d'un tableau (par exemple « Se rattacher » à un Nœud trouvé)
sont des boutons sur sa ligne. Ajout du 2026-11-22 : une ligne modifiable (utilisateur,
volume du Nœud) porte un seul bouton « Éditer », qui ouvre un **panneau**
modal regroupant ses modifications préremplies (quota et étiquette d'un
utilisateur ; chemin, capacité, retrait, perte et effacement d'un volume) ;
la page ne répète pas ces formulaires. Un secret remis une seule fois
(phrase d'annonce de
[`protocols.canal-noeud`](../04-protocols/canal-noeud.md)) s'affiche dans
un panneau qui ne se ferme qu'après confirmation, en grille de 6 × 4 mots,
avec la démarche à suivre — jamais dans un message éphémère.

Ergonomie commune (ajout du 2026-11-22) : les deux dashboards partagent
le même moteur d'affichage (celui du Connecteur sert aussi le Nœud
administré à distance). Tableaux : filtre, tri, 10 / 50 / 100 lignes par
page ou un nombre saisi, export CSV ; une ligne de message s'ouvre dans un
panneau au clic (texte complet, réponse en zone de texte multiligne,
suppression), et porte aussi ses boutons (Répondre, Supprimer, Écrire,
Éditer). Les longs textes se saisissent en zone multiligne. Un chemin
(volume du Nœud, dossier synchronisé) se saisit ou se choisit avec un
explorateur (disques sous Windows, `/`, dossier personnel et points de
montage `/media`, `/run/media`, `/mnt` ou `/Volumes` ailleurs ; création
d'un dossier) qui affiche l'espace total, disponible et le pourcentage
restant du disque. Les sous-sections de la Configuration du Nœud sont des
onglets. L'assistant du Connecteur propose l'accès « Dossier » (chemin) ou
« Périphérique » (lettre libre sous Windows, point de montage ailleurs).

## Dashboard Connecteur

Nœud rattaché et son état de joignabilité, espace disponible / total et
pourcentage utilisé (quota et occupation communiqués par le Nœud dans
`RootState`, [`protocols.echange-blocs`](../04-protocols/echange-blocs.md) —
c'est aussi la taille du lecteur monté), palier d'alerte de migration en
cours (ancienneté de `inactivity_detected_at`), état de la
[`protocols.write-queue`](../04-protocols/write-queue.md) (mutations en
attente, taille, dernière synchronisation, entrées rejetées pour
dépassement de quota — [`protocols.quota-sync`](../04-protocols/quota-sync.md)),
état de l'écriture d'urgence
([`protocols.espace-secours`](../04-protocols/espace-secours.md) —
partenaires utilisés, estimation du quota consommé par les autres
Connecteurs), page « Messages du Nœud » : alerte en tête de la vue
d'ensemble jusqu'à son acquittement, messages reçus, écriture au Nœud
([`protocols.canal-noeud`](../04-protocols/canal-noeud.md) ; côté Nœud,
page « Messages » : messages reçus et envoyés, création de la clé
d'annonce, envoi d'une alerte avec la phrase d'annonce), historique des incidents d'intégrité
([`protocols.integrite-lecture`](../04-protocols/integrite-lecture.md)),
configuration de `Q_max` (4 GiO par défaut) et de l'intervalle de
surveillance (5 minutes par défaut), lettre du lecteur monté (lettre libre
autre que `C:` ; le lecteur est démonté puis remonté sans redémarrer S3m,
l'ancienne lettre est rétablie en cas d'échec, les modifications en attente
sont conservées), accès aux fichiers (lecteur ou dossier, et
emplacement du dossier). Dans les deux dashboards, chaque libellé est explicite et
porte une infobulle (marque ⓘ) qui l'explique. État de l'**espace de travail** de
l'[écriture différée](../04-protocols/ecriture-differee.md) (occupation,
réserve `workspace_reserve_bytes`), paramètres du délai de synchronisation
différée, indicateur des synchronisations en attente et action
« synchroniser maintenant ».

## Déploiement

- **Nœud** : image conteneurisée officielle Docker (et binaire autonome),
  NAS/serveurs domestiques/Raspberry Pi.
  Pour des essais, `s3m-node init <répertoire> --identite` crée un Nœud
  avec une identité neuve, sans assistant ; les scripts `impl/essais/`
  (`creer-noeuds.ps1`, `lancer-noeuds.ps1`, `arreter-noeuds.ps1`) créent,
  lancent et arrêtent des dizaines de Nœuds sur une même machine, chacun
  avec ses ports, sans UPnP, rattachement automatique des utilisateurs
  activé.
- **Connecteur** : **binaire Rust natif**, indépendant du Nœud (peut
  tourner sur une machine distincte). Le moteur (cryptographie, système de
  fichiers, DHT) est entièrement en Rust. **TypeScript ne concerne que
  l'interface** : le dashboard est un ensemble de fichiers statiques servis
  par le binaire ; aucun runtime JavaScript n'est requis à l'exécution. Le
  lecteur monté ([`protocols.acces-applicatif`](../04-protocols/acces-applicatif.md))
  nécessite WinFsp ou FUSE ; sans eux, le [mode dossier](../04-protocols/acces-applicatif.md#mode-dossier)
  ne demande rien à installer. Sous Windows, l'assistant propose le mode
  dossier par défaut, même si WinFsp est installé (2026-11-23).

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
  la [phrase de récupération](../03-crypto/identity-derivation.md#phrase-seule)
  (24 mots), ou reprise d'une identité existante par ses 24 mots, recherche des
  Nœuds du réseau local
  ([`network.bootstrap`](../01-network-dht/bootstrap.md#reseau-local)),
  bouton « Se rattacher » sur chaque Nœud trouvé ou saisie manuelle de son
  adresse, puis démarrage normal et ouverture du tableau de bord ; le
  rattachement est demandé automatiquement
  ([`protocols.partenariat-automatique`](../04-protocols/partenariat-automatique.md)).
  Un Nœud « à configurer » trouvé se configure depuis sa ligne de la liste
  (saisie du code d'appairage, bouton « Ouvrir son assistant ») ; la phrase
  de 24 mots s'affiche en grille numérotée de 6 lignes × 4 colonnes ;
  l'accès aux fichiers (lecteur ou [dossier](../04-protocols/acces-applicatif.md#mode-dossier))
  se choisit dès l'assistant, le dossier seul si WinFsp est absent ; le dashboard du Connecteur permet ensuite
  d'administrer son Nœud à distance avec le code 2FA
  ([`deploiement.appairage-admin`](appairage-admin.md)).
- **Changer de Nœud** (menu de l'icône, ou tableau de bord avec
  confirmation) : seule cette identité s'arrête (tâches, lecteur ou dossier
  synchronisé, tableau de bord), puis son assistant s'ouvre ; les autres
  identités continuent (2026-11-23). L'identité (phrase de récupération,
  sel d'attachement) est conservée ; `connector.json` et les données
  locales sont renommés avec un suffixe horodaté, jamais effacés. Si un
  fichier reste ouvert, S3m redémarre entièrement, comme auparavant.
  **Version des fichiers reprise** (2026-11-23) : le nouvel espace local
  repart de la racine validée de l'ancien (racine, sel, version de clé) si
  le Nœud choisi la détient encore (même Nœud, ou Nœud qui l'a reprise par
  [`protocols.migration-noeud`](../04-protocols/migration-noeud.md)) ;
  sinon, de celle publiée dans l'entrée User. Il ne repart jamais d'un
  espace vide quand des fichiers existent ailleurs.

### Explorateur {: #explorateur }

Ajout du 2026-11-23 : page « Explorateur » du dashboard Connecteur
(`explorer.html`, servie comme la carte du Nœud). Navigation dans l'espace,
création de dossiers, envoi de fichiers et d'arborescences (bouton ou
glisser-déposer), téléchargement, renommage et déplacement (y compris par
glisser-déposer sur un dossier), suppression (dossier avec son contenu),
partage ([`protocols.partage`](../04-protocols/partage.md)) et, en mode
dossier, « garder sur cet appareil ». Les contenus transitent par morceaux
de 512 Kio sur l'API locale ; chaque modification est synchronisée avec le
Nœud. « Partagés avec moi » y est en lecture seule.

### Contacts {: #contacts }

Ajout du 2026-11-23 : page « Contacts » du dashboard Connecteur. Un contact
= identifiant S3m (`user_id`) et pseudo facultatif choisi par l'utilisateur,
uniques ; copie locale dans `contacts.json` (données de l'identité),
synchronisée entre appareils, chiffrée, par l'entrée User
([`deploiement.contacts`](contacts.md)). Édition par ligne (pseudo, identifiant, suppression). Le
destinataire d'un partage accepte le pseudo d'un contact ou un identifiant ;
les écrans affichent le pseudo d'un contact à la place de l'empreinte
(destinataire d'un partage donné, propriétaire d'un partage reçu, lu dans
son autorisation signée). Fiche d'un contact : partages faits avec lui
et reçus de lui, « Partager avec… ». Partage reçu d'un inconnu : « Ajouter
aux contacts » (identifiant lu dans l'autorisation). « Mon identifiant » :
identifiant, empreinte et QR code à communiquer. Export (fichier
`contacts-s3m.json` ou texte à copier) et import (contacts déjà présents
gardés, pseudo déjà pris abandonné).

### Partages {: #partages }

Ajout du 2026-11-22 : page « Partages » du dashboard Connecteur et
dossier `Partagés avec moi` du lecteur — voir
[`protocols.partage`](../04-protocols/partage.md#connecteur).

### Plusieurs identités {: #plusieurs-identites }

Ajout du 2026-11-22 (étape 2 de l'usage de plusieurs identités, après les
[pseudos](pseudos.md)). `S3m.exe` fait tourner en même temps plusieurs
identités Utilisateur, chacune comme un Connecteur complet et indépendant.

- **Rangement** : l'identité d'origine reste dans `%APPDATA%\S3m` ; chaque
  identité ajoutée a son dossier `%APPDATA%\S3m\identites\<n>` (n = 2, 3…)
  avec sa configuration, sa phrase de récupération, ses données et sa clé
  d'appareil. Rien ne relie deux identités vues de l'extérieur.
- **Ajout** : menu « Ajouter une identité… » : assistant de premier
  lancement dans ce dossier (nouvelle phrase de 24 mots, ou phrase
  existante). Une identité n'est jamais dérivée d'une autre phrase.
- **Accès aux fichiers** : une lettre de lecteur libre par identité, ou un
  [dossier synchronisé](../04-protocols/acces-applicatif.md#mode-dossier) :
  `%USERPROFILE%\S3m` pour l'identité d'origine, `%USERPROFILE%\S3m <n>`
  pour les autres (Windows refuse un dossier synchronisé dans un autre).
- **Une icône** : sa couleur suit l'identité dans le pire état ; le menu a
  un sous-menu par identité, nommé `pseudo · empreinte` (ouvrir les
  fichiers, le tableau de bord — un par identité, sur son propre port —,
  synchroniser, suspendre, changer de Nœud, retirer l'identité).
- **Retrait** (second clic de confirmation ; l'identité d'origine seulement
  s'il en reste une autre) : S3m redémarre sans elle ; son dossier est
  renommé `<n>.retiree-<horodatage>` (pour l'origine, ses fichiers vont
  dans `identites\1.retiree-<horodatage>`, le dossier de l'application
  gardant journaux et identités), jamais effacé d'office (voir ci-dessous), et
  son dossier synchronisé déconnecté. Le nom du sous-menu suit le pseudo
  de l'identité.
- **Identités archivées** (menu de l'icône, grisé s'il n'y en a pas) : une
  entrée par identité retirée, `pseudo — retirée le JJ/MM/AAAA`, avec
  *Restaurer* (relancée aussitôt sous le premier numéro libre, à partir
  de 2) et *Supprimer définitivement* (second clic de confirmation ; son
  dossier est effacé de ce poste, phrase de récupération comprise : seule
  la phrase notée permet ensuite de la retrouver).
- Deux identités peuvent être rattachées au même Nœud (deux Utilisateurs
  distincts pour lui) ou à des Nœuds différents.

## API locale {: #api-locale }

Chaque dashboard dialogue avec son moteur par une **API locale** (HTTP et
WebSocket). Les mêmes protections s'appliquent au Nœud et au Connecteur
(arbitrage du 2026-11-19) :

- **Liaison** : uniquement `127.0.0.1`, sur un port connu du processus.
- **Jeton** : un secret aléatoire de **256 bits**, jamais écrit dans l'URL
  de requête, transmis dans l'en-tête `Authorization: Bearer`. Comparaison
  à temps constant. Arbitrage du 2026-11-21 (favoris) : le jeton et le port
  du dashboard du Nœud et du Connecteur sont **conservés** d'un démarrage à
  l'autre dans `dashboard.json` du répertoire de données (port configuré
  prioritaire ; port libre si le port conservé est pris) ; supprimer ce
  fichier renouvelle le jeton. Assistant de premier lancement et
  administration à distance : jeton propre à chaque démarrage.
- **Remise du jeton au dashboard** : à l'ouverture du navigateur, le jeton
  est placé dans le **fragment d'URL** (`#…`), qui n'est jamais envoyé au
  serveur, ni journalisé, ni transmis dans `Referer`. La page le retient
  dans le stockage local du navigateur, propre à cette adresse, et le
  retire de la barre d'adresse : l'adresse nue (`http://127.0.0.1:<port>/`)
  peut être mise en favori.
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
