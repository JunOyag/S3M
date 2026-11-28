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

### Garde-fou d'horloge {: #horloge }

Ajout du 2026-11-25. À chaque cycle (30 s), le Nœud compare l'heure système
au temps réellement écoulé ; un écart de plus d'un jour (heure avancée ou
reculée), une heure antérieure au dernier arrêt ou un arrêt de plus de
7 jours **gèlent les suppressions liées au temps** : Utilisateurs
inactifs ([`protocols.partenariat-automatique#inactivite`](../04-protocols/partenariat-automatique.md#inactivite)),
versions expirées ([`protocols.historique-versions`](../04-protocols/historique-versions.md)),
blocs libérés, partenaires silencieux et analyse de leur disponibilité
([`protocols.volatilite-reparation`](../04-protocols/volatilite-reparation.md)),
dépôts de secours. Le gel survit à un redémarrage ; le tableau de bord
l'affiche (bandeau, carte « Horloge », section de la vue d'ensemble) et
l'opérateur le lève après avoir vérifié l'heure (« L'heure est juste :
reprendre »).

### Alertes hors tableau de bord {: #alertes }

Ajout du 2026-11-25. Les alertes critiques du Nœud — défaillance d'un
disque ([`securite.integrite-autoreparation#defaillance`](../05-securite/integrite-autoreparation.md#defaillance)),
maintenance, horloge à vérifier (§ précédent) — sont envoyées à leur
apparition, et de nouveau si elles disparaissent puis reviennent, sur les
canaux de l'onglet « Alertes » de la configuration : fenêtre sur le bureau
de la machine du Nœud (Windows, activée par défaut), appel HTTP POST
`{"nœud", "alerte", "détail"}` (webhook), courriel (serveur SMTP, STARTTLS
ou TLS, destinataires séparés par des virgules). Un envoi en échec est
noté au journal ; « Envoyer une alerte d'essai » vérifie les canaux.

## Dashboards : écrans et menu {: #ecrans }

### Saisies et présentation {: #durees }

Ajout du 2026-11-26. Toute durée se saisit sous la forme « 10s », « 10min »,
« 2h » ou « 7d » (« 7j » accepté ; un nombre seul est dans l'unité du
champ) ; la valeur saisie est expliquée au survol (« 7 jours ») et le
libellé du champ rappelle les formats. Les durées affichées dans les
tableaux sont écrites en clair. L'espace offert aux partenaires se règle en
Mio. Les cases à cocher sont des interrupteurs ; le logo a un fond blanc
(thème foncé). Une saisie en cours garde le focus malgré le rafraîchissement
périodique ; les formulaires de même nom sont réunis dans un seul onglet.
Une durée qui n'est pas un nombre entier de l'unité du champ (« 2s » pour
un champ en jours) est refusée avec un message, jamais arrondie. Les
messages de retour restent 15 s à l'écran et se ferment d'un clic.

### Journal {: #journal }

Ajout du 2026-11-26. L'onglet Journal (Diagnostic) filtre les événements
par période (« Du … au … », date et heure) en plus du filtre texte. Le
journal est gardé sur disque — `journal.log` du Nœud, `logs/s3m.log` de
S3m — et purgé chaque jour au-delà de sa conservation (90 jours par
défaut) : réglage « conservation du journal » de la configuration du Nœud,
formulaire de l'onglet Journal du Connecteur (`logs/conservation-jours`,
commun à toutes les identités du poste).

### Clé d'alerte du Nœud {: #cle-alerte }

Une demande de remplacement de la clé d'alerte
([`protocols.canal-noeud`](../04-protocols/canal-noeud.md)) s'affiche en
tête de l'accueil, même en mode simple, avec une explication pour un
public non averti ; la décision (accepter, refuser, chacune confirmée) se
prend dans la fenêtre du message. « J'ai lu l'alerte » est dans la fenêtre
de l'alerte, et sur l'accueil tant qu'elle n'est pas acquittée.

### Favoris, éléments récents et versions {: #favoris }

- **Favoris** : étoile de chaque ligne de l'Explorateur (un clic) ; liste
  repliable en tête de l'accueil, renommable, ouvrant l'Explorateur au bon
  dossier.
- **Récents** : les 10 derniers éléments envoyés ou téléchargés depuis
  l'Explorateur, repliables, sur l'accueil.
- **Versions** (« Historique des versions ») : regroupées par jour (dépliable) ;
  pour un dossier, chaque version indique ses ajouts, suppressions et
  modifications par rapport à la précédente (sous-arbres identiques
  sautés), la version actuelle en tête.
- **Partager / Contacts** : partager se fait uniquement depuis l'Explorateur ;
  « Ajouter un contact » et « Ajouter un partage reçu » ouvrent une
  fenêtre sous leur liste ; le pseudo se règle dans la section Utilisateur.


### Mode simple et mode expert {: #modes }

Ajout du 2026-11-25. Chaque tableau de bord a deux jeux d'écrans : `pages`
(mode expert, tous les écrans, réglages et détails techniques) et
`pages simples` (mode simple, **par défaut**). L'interrupteur « Mode
expert » de l'en-tête bascule de l'un à l'autre ; le choix est mémorisé
dans le navigateur. En mode simple, seules les sections citées par chaque
écran s'affichent ; les sections propres au mode simple ne s'affichent
jamais en mode expert.

- **Connecteur** : Accueil (« En un coup d'œil » : état en une phrase avec
  voyant, que faire, espace, envois en attente ; nouvelle phrase et mise en
  route s'il y a lieu), Mes fichiers (Explorateur, versions et retour
  arrière), Partager (partages et contacts), Mon compte (identité, espace,
  accès aux fichiers, historique, changement de Nœud ou d'identité),
  Messages (seulement s'il y en a).
- **Nœud** : Accueil (alertes, maintenance, horloge, quatre voyants
  « Santé du Nœud » — disques, réseau, partenaires, utilisateurs — avec la
  conduite à tenir), Utilisateurs (tableau réduit), Disques (volumes,
  alertes, marche à suivre « Remplacer un disque »), Messages, Réglages
  essentiels (nom, accueil automatique, alerte d'essai).


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
  Tant qu'une identité nouvelle n'est pas rattachée (autorisation de secours
  encore jamais reçue) ou que l'accès à ses fichiers n'est pas ouvert, sa vue
  d'ensemble affiche la **mise en route** : identité créée, preuve d'identité
  (VDF, 1 à 2 min une seule fois), rattachement au Nœud, accès aux fichiers,
  protection continue — chaque étape avec son état et son explication.

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
un élément d'un tableau (par exemple « Choisir » un Nœud trouvé)
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
  bouton « Choisir » sur chaque Nœud trouvé (qui ne fait que le mettre en
  évidence) ou saisie manuelle de son adresse ; un bouton unique « Démarrer
  sous cette identité », en bas de page, prend en compte tout ce qui est
  saisi (Nœud, accès aux fichiers), puis démarrage normal et ouverture du tableau de bord ; le
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

Ergonomie (ajout du 2026-11-27) :

- **Ouvrir** : double-clic (ou Entrée) ouvre un dossier ou télécharge un
  fichier ; une ligne fixe « Dossier parent » est en tête, sauf à la racine.
- **Pagination** : 10, 50 ou 100 lignes par page, ou un autre nombre
  (mémorisé), avec numéro de page.
- **Sélection** : clic (un élément), Ctrl+clic (ajout unitaire), Maj+clic
  (intervalle), case d'en-tête (page affichée), « Tout sélectionner » ou
  Ctrl+A (toutes pages). Une barre fixée en bas de l'écran (la liste ne se
  décale pas) indique le nombre d'éléments et leur volume, et agit sur toute
  la sélection : télécharger (fichiers un par un), déplacer, rendre
  disponible hors connexion, libérer l'espace, supprimer.
- **Renommer** : nouveau nom, ou chemin relatif ou absolu. Une destination
  sous un dossier inexistant est refusée et signalée dans la fenêtre.
- **Organiser** (sous-menu) : « Déplacer… » (fenêtre de navigation dans les
  dossiers de l'espace), favoris, « Couleur de dossier… » (8 couleurs
  prédéfinies, couleurs récentes, couleur libre). Les couleurs sont gardées
  sur l'appareil (`couleurs.json`) et suivent les déplacements.
- **Actions rapides** sur la ligne survolée ou sélectionnée : partager,
  télécharger (fichiers), renommer, favori.
- **Élément partagé** : icône devant le nom. Un clic ouvre ses partages
  actifs : afficher le lien ou l'invitation, retirer, nouveau partage.
- **Fenêtres** : confirmations et saisies dans des fenêtres stylées, et non
  plus celles du navigateur. Entrée valide (Échap annule) ; une erreur
  s'affiche dans la fenêtre.
- **Page** : son titre porte le pseudo de l'identité.

Nœud injoignable (ajout du 2026-11-26) : avec des partenaires en ligne, les
fichiers absents de l'appareil sont reconstruits depuis la parité
(lecture de secours) ; sans partenaire joignable, ou après un échec récent,
ils sont marqués « indisponible hors ligne » et leur téléchargement est
refusé aussitôt, avec une explication ; le lecteur et le dossier synchronisé
répondent de même « fichier hors ligne » à l'Explorateur Windows au lieu de
le bloquer. La reconstruction d'un bloc depuis les partenaires est bornée à
20 s, et suspendue 60 s après un échec. Chaque fichier ou dossier propose
« Rendre disponible hors connexion » (copie complète sur l'appareil, jamais
libérée, nouveautés copiées à chaque contact avec le Nœud) et « Libérer
l'espace » (copies locales retirées, éléments gardés et modifications non
envoyées exceptés), en mode lecteur comme en mode dossier.

Ajout du 2026-11-23 : page « Explorateur » du dashboard Connecteur
(`explorer.html`, servie comme la carte du Nœud). Navigation dans l'espace,
création de dossiers, envoi de fichiers et d'arborescences (bouton ou
glisser-déposer), téléchargement, renommage et déplacement (y compris par
glisser-déposer sur un dossier), suppression (dossier avec son contenu),
partage ([`protocols.partage`](../04-protocols/partage.md)) et, en mode
dossier, « garder sur cet appareil ». Les contenus transitent par morceaux
de 512 Kio sur l'API locale ; chaque modification est synchronisée avec le
Nœud. « Partagés avec moi » y est en lecture seule. Les actions d'un
élément sont regroupées dans un menu « ⋯ » en bout de ligne, ouvert aussi
par un clic droit sur la ligne (ajout du 2026-11-24) ; en mode dossier, il
propose aussi « Libérer l'espace » (fichier ou dossier non gardé : contenu
déjà envoyé au Nœud retiré du disque, comme « Libérer de l'espace »).

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
identifiant, empreinte et QR code à communiquer. « Exporter » (à côté de
« Ajouter un contact ») télécharge `contacts-s3m.json` ; « Importer »
ouvre le choix d'un fichier JSON (contacts déjà présents gardés, pseudo
déjà pris abandonné). Même panneau en mode simple et en mode expert ; la
fiche d'un contact ne propose plus de partager (c'est l'Explorateur qui
partage). Ajout du 2026-11-26 : la fenêtre
« Ajouter un contact » propose « Scanner un QR code » (caméra du PC ou du
téléphone, décodeur jsQR embarqué, aucun envoi d'image) qui remplit
l'identifiant ; le bouton est grisé, avec une explication au survol, sans
caméra ou hors contexte sûr (tableau de bord ouvert en http distant).

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
  synchroniser, suspendre, changer de Nœud, archiver l'identité).
- **Archivage** (« Archiver cette identité », sans confirmation ; l'identité
  d'origine seulement s'il en reste une autre) : S3m redémarre sans elle ; son dossier est
  renommé `<n>.retiree-<horodatage>` (pour l'origine, ses fichiers vont
  dans `identites\1.retiree-<horodatage>`, le dossier de l'application
  gardant journaux et identités), jamais effacé d'office (voir ci-dessous), et
  son dossier synchronisé déconnecté. Le nom du sous-menu suit le pseudo
  de l'identité.
- **Identités archivées** (menu de l'icône, grisé s'il n'y en a pas) : une
  entrée par identité archivée, `pseudo — archivée le JJ/MM/AAAA`, avec
  *Réactiver* (relancée aussitôt sous le premier numéro libre, à partir
  de 2) et *Supprimer définitivement* (fenêtre de confirmation, « Non » par
  défaut, rappelant que seule la phrase de récupération notée permet
  ensuite de retrouver les données et que, sans appareil connecté, les
  entrées de l'identité dans l'annuaire expirent au bout de 6 mois ; son
  dossier est effacé de ce poste, phrase de récupération comprise).
- Deux identités peuvent être rattachées au même Nœud (deux Utilisateurs
  distincts pour lui) ou à des Nœuds différents.

### Coffre local des phrases secrètes {: #coffre-local }

Ajout du 2026-11-26. Les phrases de récupération (`user.seed` du
Connecteur, `node.seed` du Nœud) ne restent plus en clair sur le disque :

- **Coffre du système** (Windows : Gestionnaire d'identification ;
  macOS : Trousseau) : au démarrage, les exécutables y rangent une phrase
  encore en clair ; le fichier `<phrase>.coffre` ne garde que la référence.
  Le programme démarre seul, sous le compte qui l'a rangée.
- **Phrase de passe** (Nœud ; Linux sans coffre du système) : la phrase
  est chiffrée dans `<phrase>.coffre` (Argon2id puis ChaCha20-Poly1305,
  [`crypto.symmetric-suite`](../03-crypto/symmetric-suite.md)). Le Nœud
  démarre **verrouillé** : son tableau de bord ne propose que le
  déverrouillage. À distance, le canal d'administration
  ([`deploiement.appairage-admin`](appairage-admin.md)) écoute sous une
  **clé de déverrouillage** distincte (en clair dans le coffre, sans
  autre pouvoir) et n'accepte que `Unlock { passphrase }`, essais limités
  comme le 2FA. Le Nœud ouvert annonce cet identifiant (`Hello.unlock`) ;
  le Connecteur le retient à chaque connexion d'administration et s'y
  adresse (« Administrer mon Nœud à distance », champ « phrase de
  passe »). « Redémarrer le Nœud » transmet la phrase au nouveau
  processus (entrée standard) sans la redemander.
- **En clair** : sur demande explicite (« Remettre en clair », tableau de
  bord local seulement) ; plus de migration automatique ensuite. Le
  tableau de bord le signale (⚠).

L'ancienne phrase gardée après un changement d'identité suit le même
rangement ; supprimer une identité archivée la retire du coffre. Limite :
le coffre protège contre la lecture du disque, pas contre un programme
malveillant qui s'exécute sous le compte de l'utilisateur.

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

### 2FA du Nœud {: #2fa-noeud }

Ajout du 2026-11-28, même principe que le 2FA des utilisateurs
([`securite.incidents-compromissions#2fa`](../05-securite/incidents-compromissions.md#2fa)).

- **Activation** : section « 2FA du nœud » (accueil en mode simple, page
  Administration à distance en mode expert). « Afficher le QR code » montre
  le secret TOTP de l'administration à distance pendant 2 min, puis un code
  à 6 chiffres le confirme. L'état est gardé dans
  `data/operations-noeud.json`. Régénérer le 2FA change de série : il est à
  réactiver.
- **Bandeau rouge** tant que le 2FA n'est pas activé, avec les risques
  expliqués simplement.
- **Actions critiques** : remplacer la clé d'annonce, envoyer une alerte de
  compromission, appliquer des modifications de volumes qui déclarent un
  volume perdu ou en effacent un, remettre la phrase secrète en clair,
  régénérer ou désactiver le 2FA. Leur formulaire porte un champ « code
  2FA » :
  - avec un code valide, elles sont exécutées aussitôt (un code ne sert
    qu'une fois) ;
  - sans code, ou si le 2FA n'est pas activé, elles sont différées de
    72 h : notées au journal, signalées par les alertes de l'opérateur et
    annulables depuis « Opérations critiques en attente » ;
  - à l'échéance, une modification de volumes est abandonnée si la liste a
    changé depuis la demande.

### Organisation des écrans {: #organisation }

Ajout du 2026-11-28.

- **Noms** : chaque écran porte le même nom en mode simple et en mode
  expert (Accueil, Disques, Mes fichiers, Partages, Messages, Mon
  compte…).
- **Réglages** : tous les réglages sont rassemblés dans un écran, avec un
  onglet par thème. Cet écran est Configuration côté Nœud et Paramètres
  côté Connecteur, présent dans les deux modes. Les autres écrans ne gardent
  que des actions. Sous une section qui a des réglages, un bouton
  « Configurer » ouvre cet écran sur le bon onglet (`configurer` :
  section → onglet dans la description de l'écran).
- **Onglets du Nœud** : Réseau, Relais, Partenaires, Contrôles,
  Administration à distance, Utilisateurs (rattachement automatique,
  nombre maxi d'utilisateurs, délai d'inactivité avant suppression en jours
  entiers), Alertes, Journal, Géolocalisation (mise à jour de la base,
  enregistrement de l'adresse des utilisateurs), Identité, Espace de
  secours.
- **Onglets du Connecteur** : Identité (pseudo), Mon Nœud, Fichiers (accès,
  libération automatique, protection contre le vol), Journal.
- **Utilisateurs du Nœud** : « Ajouter un utilisateur » (rattachement
  manuel, en fenêtre) et « Configuration » sous la liste.
- **Fichiers et synchronisation** (Connecteur) : « Libérer de l'espace »
  et « Toujours garder sur cet appareil » ne s'y trouvent plus
  (l'Explorateur le fait). « Nettoyer les blocs inutilisés » (ancien
  « Libérer les anciennes versions ») libère chez le Nœud les blocs que ni
  la version actuelle ni l'historique n'utilisent. Les versions gardées ne
  sont jamais touchées, à la différence de « Purger tout l'historique »,
  protégée par le 2FA. Le Nœud garde de toute façon un bloc libéré aussi
  longtemps que l'historique ([`protocols.echange-blocs#liberation`](../04-protocols/echange-blocs.md#liberation)).
- **Connexion** : « ● En ligne » ou « ● Hors ligne » dans l'en-tête.
- **Explorateur** : recliquer sur la seule ligne sélectionnée la
  désélectionne. Les icônes d'action n'apparaissent qu'au survol.

### Affichage commun des tableaux de bord {: #affichage }

Ajout du 2026-11-27, Nœud et Connecteur :

- **Thème** : sélecteur clair / foncé / système dans la barre du haut.
  Le choix est mémorisé dans le navigateur et suivi par l'Explorateur.
- **Copier** : bouton presse-papiers, avec infobulle, à côté de chaque
  identifiant, clé, sel, empreinte ou racine.
- **Bandeau persistant** (`bandeau`) en haut de l'écran. Le Connecteur
  l'affiche en rouge tant que le 2FA n'est pas activé, avec les risques
  expliqués simplement et un bouton « Activer le 2FA maintenant ». S3m.exe
  le rappelle aussi par une notification au lancement.
- **Utilisateurs rattachés** (Nœud) : colonne « Pseudo / Empreinte ». La
  clé publique (avec « Copier ») et la racine sont dans la fenêtre
  « Éditer », où « Étiquette » devient « Pseudo ».
- **Boutons** : les formulaires réduits à un bouton (Ajouter un contact,
  Exporter, Importer…) sont côte à côte. Les tableaux clé / valeur ont des
  libellés de largeur fixe : les valeurs, y compris dans les sous-tableaux,
  sont alignées d'une section à l'autre.
- **Hors connexion** : « Ne plus garder hors connexion » sur un élément d'un
  dossier gardé est refusé, avec une explication. Tout le sous-arbre est
  gardé : il faut retirer la marque sur le dossier.
- **Volumes** (Nœud) : le seul volume actif ne propose ni « Retirer » ni
  « Déclarer perdu ». La fenêtre explique pourquoi et dit d'ajouter d'abord
  un nouveau volume.
- **Mes appareils** : badge « Cet appareil » à droite du nom ; colonnes
  « Dernière connexion » : adresse IP (« IP (Pays) » avec la carte de
  géolocalisation du Nœud) et date et heure
  ([dernière connexion](../05-securite/incidents-compromissions.md#nouvel-appareil)).
- **« Toujours libérer l'espace »** (Connecteur, mode expert, Accès aux
  fichiers) : quand plus rien n'attend d'être reçu par le Nœud ni dispersé
  chez ses partenaires, le contenu local est libéré, sauf les éléments
  gardés hors connexion. Rien n'est lisible sur l'appareil quand S3m ne
  tourne pas.
- **Barre des tâches** : quand l'icône est dans la moitié droite de
  l'écran, le menu s'ouvre à gauche du curseur.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
