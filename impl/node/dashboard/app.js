// Dashboard local S3m (Nœud et Connecteur, même fichier).
// Jeton remis par le fragment d'URL (#token=…), retenu par le navigateur
// pour cette adresse et retiré de la barre d'adresse : l'adresse nue peut
// être mise en favori (docs/07-deploiement/packaging.md § API locale).
//
// Le serveur décrit tout en JSON : sections (objets, listes, tableaux),
// actions (formulaires) et, dans les tableaux, boutons par ligne (`_actions`).
"use strict";

const hashParams = new URLSearchParams(location.hash.slice(1));
// Jeton retenu par le navigateur pour cette adresse (favoris) ; celui du
// fragment, s'il y en a un, le remplace.
const token = rememberToken(hashParams.get("token"));
function rememberToken(t) {
  try {
    if (t) localStorage.setItem("s3m-token", t);
    return t || localStorage.getItem("s3m-token") || "";
  } catch (_) {
    return t || "";
  }
}
// `#token=…&page=<id>` ouvre directement un écran.
const linkedPage = hashParams.get("page");
history.replaceState(null, "", location.pathname);

const main = document.getElementById("main");
const live = document.getElementById("live");

function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}

// ---------------------------------------------------------------- libellés

// Libellés affichés et infobulles : `clé du moteur` → [texte, explication].
// Sans entrée : première lettre en majuscule, unité « (octets) » retirée
// (les tailles sont affichées en Ko, Mo, Go…).
const LABELS = {
  // ---- Généralités
  "node_id": ["Identifiant du Nœud", "Clé publique du Nœud : elle l'identifie sur le réseau S3m."],
  "peer_id": ["Identifiant réseau", "Identité libp2p du Nœud, dérivée de son identifiant."],
  "user_id": ["Identifiant de l'utilisateur", "Clé publique de l'utilisateur, affichée par son application S3m."],
  "salt": ["Sel d'attachement", "Valeur aléatoire propre au rattachement de cet utilisateur à ce Nœud (32 caractères)."],
  "addr": ["Adresse", "Adresse réseau au format /ip4/…/tcp/…/p2p/…"],
  "adresse": ["Adresse", "Adresse réseau au format /ip4/…/tcp/…/p2p/…"],
  "allowance": ["Solde accordé (fragments)", "Nombre de fragments que chaque Nœud accepte d'héberger pour l'autre (troc 1 pour 1)."],
  "enabled": ["Activé", ""],
  "max_users": ["Utilisateurs au plus", "Nombre maximal d'utilisateurs rattachés automatiquement."],
  "erreur": ["Erreur", "Dernière erreur rencontrée ; vide si tout va bien."],
  "erreurs": ["Erreurs", ""],
  "dernière erreur": ["Dernière erreur", ""],
  "important": ["Important", ""],
  "source": ["Source", ""],
  "fichier": ["Fichier", "Fichier de configuration lu au démarrage."],
  "unité": ["Unité", ""],
  "base": ["Base", ""],

  // ---- Nœud rattaché (Connecteur)
  "nœud rattaché": ["Nœud rattaché", "Le Nœud qui stocke vos fichiers."],
  "adresse configurée": ["Adresse configurée", "Adresse du Nœud enregistrée dans la configuration."],
  "adresse utilisée": ["Adresse utilisée", "Adresse par laquelle le Nœud est joint en ce moment (elle peut différer après un changement de réseau)."],
  "joignable": ["Joignable", "Le Nœud répond-il aux requêtes de ce connecteur ?"],
  "dernier contact": ["Dernier contact", "Dernière réponse reçue du Nœud."],
  "indisponible depuis (s)": ["Indisponible depuis (secondes)", "Durée depuis laquelle le Nœud ne répond plus."],
  "espace": ["Espace", "Votre quota chez le Nœud : c'est aussi la taille du lecteur monté."],
  "libre (octets)": ["Libre", "Espace encore disponible."],
  "total (octets)": ["Total", "Quota attribué par le Nœud."],
  "utilisé (octets)": ["Utilisé", "Espace occupé par vos fichiers chez le Nœud."],
  "% utilisé": ["Utilisé (%)", "Part du quota occupée."],
  "utilisé (%)": ["Utilisé (%)", "Part de la capacité occupée."],
  "rattachement automatique": ["Rattachement automatique", "Rattachement d'un utilisateur sans intervention de l'opérateur du Nœud, dans les limites fixées par celui-ci."],
  "en cours": ["En cours", ""],
  "quota attribué (octets)": ["Quota attribué", "Espace accordé par le Nœud lors du rattachement automatique."],
  "dernière tentative": ["Dernière tentative", ""],

  // ---- Lecteur et synchronisation (Connecteur)
  "lecteur": ["Lecteur", "Lecteur réseau où apparaissent vos fichiers S3m."],
  "point de montage": ["Lettre du lecteur", "Lettre sous laquelle vos fichiers apparaissent dans l'Explorateur."],
  "lecteur monté": ["Lettre du lecteur", "Lettre sous laquelle vos fichiers apparaissent dans l'Explorateur."],
  "lettre du lecteur": ["Lettre du lecteur", "Lettre libre autre que C:, par exemple S:."],
  "monté": ["Monté", "Le lecteur est-il visible dans l'Explorateur ?"],
  "erreur de montage": ["Erreur de montage", "Raison pour laquelle le lecteur n'a pas pu être monté."],
  "modifications en attente": ["Modifications en attente", "Fichiers et dossiers modifiés pas encore envoyés au Nœud."],
  "synchronisations planifiées": ["Synchronisations planifiées", "Fichiers dont l'envoi est programmé (après un court délai sans modification)."],
  "dernière synchronisation": ["Dernière synchronisation", "Dernier envoi réussi des modifications au Nœud."],
  "erreur de synchronisation": ["Erreur de synchronisation", "Raison du dernier échec d'envoi ; un nouvel essai est fait automatiquement."],
  "conflit (racine du Nœud)": ["Conflit", "Un autre appareil a modifié vos fichiers en même temps ; rien n'est perdu."],
  "file d'écriture": ["File d'écriture hors ligne", "Modifications gardées sur ce PC pendant une coupure réseau."],
  "mutations en attente": ["Modifications en attente", ""],
  "taille (octets)": ["Taille", ""],
  "Q_max (octets)": ["Budget hors ligne", "Volume maximal de modifications gardées pendant une coupure (Q_max, 4 Gio par défaut)."],
  "intervalle de surveillance (s)": ["Intervalle de surveillance (secondes)", "Fréquence des vérifications de la joignabilité du Nœud."],
  "configuration": ["Configuration", ""],

  // ---- Écriture d'urgence (Connecteur)
  "écriture d'urgence": ["Écriture d'urgence", "Si seul votre Nœud est injoignable, vos modifications sont déposées, chiffrées, chez des Nœuds de secours, puis récupérées à son retour."],
  "partenaires de secours (n_secours)": ["Nœuds de secours", "Nombre de Nœuds distincts entre lesquels les dépôts d'urgence sont répartis."],
  "dernier dépôt": ["Dernier dépôt", ""],
  "séquence publiée": ["Version publiée", "Numéro de la dernière liste des dépôts publiée dans l'annuaire."],
  "blocs déposés à libérer": ["Blocs à libérer", "Blocs déposés chez les Nœuds de secours, libérés une fois revenus sur votre Nœud."],
  "blocs libérés": ["Blocs libérés", ""],
  "dernière réconciliation": ["Dernière réconciliation", "Dernier retour des modifications déposées vers votre Nœud."],
  "partenaire": ["Nœud", ""],
  "blocs": ["Blocs", ""],

  // ---- Identité et sécurité (Connecteur)
  "utilisateur": ["Utilisateur", ""],
  "annuaire (entrée User)": ["Annuaire (entrée utilisateur)", "Votre entrée chiffrée dans l'annuaire distribué : elle permet de retrouver vos fichiers depuis un autre appareil."],
  "connecté à la DHT": ["Connecté à l'annuaire", "L'annuaire distribué (DHT) est-il joignable ?"],
  "preuve VDF": ["Preuve d'identité calculée", "Preuve de travail qui protège le réseau des fausses identités ; calculée une seule fois."],
  "racine publiée": ["Racine publiée", "Dernier état de vos fichiers enregistré dans l'annuaire."],
  "publiée le": ["Publiée le", ""],
  "publié le": ["Publié le", ""],
  "racine restaurée depuis la DHT": ["Restaurée depuis l'annuaire", "Vos fichiers ont été retrouvés grâce à l'annuaire (nouvel appareil)."],
  "autorisation de secours": ["Autorisation de secours", "Permet de lire vos fichiers chez les partenaires si votre Nœud est hors service."],
  "expire le": ["Expire le", "Renouvelée automatiquement à chaque connexion au Nœud."],
  "incidents d'intégrité": ["Incidents d'intégrité", "Blocs reçus abîmés et signalés au Nœud."],
  "code 2FA": ["Code 2FA", "Code à 6 chiffres de votre application d'authentification."],
  "adresse d'administration": ["Adresse d'administration", "Facultatif : par défaut, adresse du Nœud et port 4003."],
  "je confirme": ["Je confirme", ""],
  "numéro": ["Numéro", ""],
  "numéro ou adresse": ["Numéro ou adresse", "Numéro du Nœud dans la liste, ou son adresse /ip4/…/p2p/…"],
  "nœuds trouvés sur le réseau local": ["Nœuds trouvés sur le réseau local", "Nœuds S3m annoncés sur votre réseau ; « Se rattacher » choisit le vôtre."],
  "j'ai déjà une identité S3m": ["J'ai déjà une identité S3m", "Reprendre une identité existante avec sa phrase de 24 mots."],
  "dossier synchronisé": ["Dossier synchronisé", "Dossier où vos fichiers apparaissent, comme avec OneDrive ou Google Drive : ils ne sont téléchargés qu'à l'ouverture."],
  "accès aux fichiers": ["Accès aux fichiers", "« lecteur » : une lettre de lecteur (WinFsp requis) ; « dossier » : un dossier synchronisé, sans rien à installer."],
  "accès": ["Accès", "« lecteur » ou « dossier » ; pris en compte au prochain lancement de S3m."],
  "dossier": ["Dossier", "Emplacement du dossier synchronisé, sur un disque local."],
  "remplacement de la clé d'alerte": ["Remplacement de la clé d'alerte", "Demande de votre Nœud, à accepter seulement après confirmation de son opérateur par un autre moyen."],
  "nouvelle clé": ["Nouvelle clé", "Empreinte de la clé d'alerte proposée."],
  "clé actuelle": ["Clé actuelle", "Empreinte de la clé d'alerte retenue jusqu'ici."],
  "pour": ["Pour", "Message adressé à vous seul, ou à tous les utilisateurs du Nœud."],

  "accès choisi": ["Accès choisi", "Modifiable ensuite dans le tableau de bord (relance de S3m)."],
  "texte": ["Message", ""],
  "de": ["De", "Utilisateur auteur du message."],
  "non lus": ["Non lus", "Messages pas encore ouverts ; ouvrir la conversation les marque lus."],
  "lu": ["Lu", "Ouvrir le message le marque lu."],
  "partages donnés": ["Partages donnés", "Vos fichiers et dossiers confiés en lecture à un utilisateur S3m ou par un lien."],
  "partages reçus": ["Partages reçus", "Partages ajoutés avec leur lien ou leur invitation ; visibles dans le dossier « Partagés avec moi »."],
  "élément": ["Élément", "Fichier ou dossier de votre espace S3m."],
  "destinataire": ["Destinataire", "Identifiant de l'utilisateur S3m ; vide pour un lien."],
  "expiration (jours)": ["Expiration (jours)", "Vide ou 0 : sans expiration."],
  "lien ou invitation": ["Lien ou invitation", "Lien s3m://partage#… ou invitation S3MS1:…"],
  "ajouté le": ["Ajouté le", ""],
  "expire le": ["Expire le", ""],
  "créé le": ["Créé le", ""],
  "écrire à mon nœud": ["Écrire à mon Nœud", "Message lu par l'opérateur de votre Nœud."],
  "messages restants sur 24 h": ["Messages restants sur 24 h", "Votre Nœud accepte 10 messages par période glissante de 24 h."],
  "quota réinitialisé le": ["Un message de plus possible le", "Date à laquelle le plus ancien de vos messages des dernières 24 h ne compte plus."],
  "dernier reçu le": ["Dernier reçu le", ""],
  "taille (octets)": ["Taille", "Taille du message ; chacun occupe 4 Kio du quota de son auteur."],
  "emplacement": ["Emplacement", "Lettre ou point de montage du lecteur."],
  "réponse": ["Réponse", "Votre réponse, lue par cet utilisateur seul à son prochain contact."],
  "espace": ["Espace", ""],
  "lettre": ["Lettre du lecteur", "Lettre libre sous laquelle vos fichiers apparaîtront dans l'Explorateur."],
  "point de montage": ["Point de montage", "Dossier vide où le lecteur sera monté."],
  "code d'appairage": ["Code d'appairage", "Code affiché par le Nœud à configurer."],
  "phrase de récupération": ["Phrase de récupération", "Les 24 mots d'une identité existante, séparés par des espaces."],
  "24 mots": ["Phrase de récupération (24 mots)", "À noter et garder en lieu sûr : elle permet de tout restaurer."],
  "QR code": ["QR code", ""],
  "code": ["Code", ""],

  // ---- Nœud : identité, utilisateurs
  "identité": ["Identité", ""],
  "identifiant temporaire": ["Identifiant temporaire", "Identité provisoire, en attendant le choix d'une identité définitive."],
  "configuration depuis un autre ordinateur": ["Configuration depuis un autre ordinateur", ""],
  "adresses d'administration": ["Adresses d'administration", "Adresses où le connecteur peut joindre ce Nœud pour l'administrer."],
  "utilisateurs": ["Utilisateurs", ""],
  "utilisateurs rattachés": ["Utilisateurs rattachés", "Utilisateurs dont ce Nœud stocke les fichiers."],
  "utilisateurs rattachés automatiquement": ["Rattachés automatiquement", ""],
  "rattachement": ["Rattachement", ""],
  "quota (Gio)": ["Quota (Gio)", "Espace accordé à l'utilisateur, en gibioctets."],
  "quota (octets)": ["Quota", "Espace accordé à l'utilisateur."],
  "quota par utilisateur (Gio)": ["Quota par utilisateur (Gio)", "Espace accordé à chaque utilisateur rattaché automatiquement."],
  "quota par utilisateur (octets)": ["Quota par utilisateur", ""],
  "utilisateurs maximum": ["Utilisateurs au plus", ""],
  "budget total (octets)": ["Budget total", "Quota par utilisateur × nombre maximal d'utilisateurs."],
  "budget utilisé (octets)": ["Budget utilisé", "Somme des quotas déjà attribués automatiquement."],
  "pays": ["Pays", "Estimé d'après l'adresse IP."],
  "racine": ["Racine", "Dernier état validé du système de fichiers de l'utilisateur."],
  "occupé (octets)": ["Occupé", ""],
  "alertes d'intégrité signalées": ["Alertes d'intégrité signalées", "Blocs signalés abîmés par les connecteurs ; réparés automatiquement."],

  // ---- Partenaires
  "partenaires": ["Partenaires", "Nœuds qui hébergent la parité de vos données (et dont vous hébergez la parité)."],
  "nœud": ["Nœud", ""],
  "score": ["Score", "Note globale de fiabilité, disponibilité et vitesse (0 à 1)."],
  "fiabilité": ["Fiabilité", "Part des contrôles réussis."],
  "disponibilité": ["Disponibilité", "Part des sondages auxquels le Nœud a répondu."],
  "vitesse": ["Vitesse", "Note de temps de réponse."],
  "latence (ms)": ["Latence (ms)", "Temps de réponse moyen."],
  "fragments confiés": ["Fragments confiés", "Fragments de parité placés chez ce partenaire."],
  "fragments reçus": ["Fragments reçus", "Fragments hébergés pour ce partenaire."],
  "solde accordé": ["Solde accordé", "Nombre de fragments accepté de part et d'autre."],
  "dernier challenge réussi": ["Dernier contrôle réussi", "Dernière preuve que le partenaire détient bien les fragments confiés."],
  "dernier échange": ["Dernier échange", ""],
  "recherche de partenaires": ["Recherche de partenaires", "Découverte et évaluation automatiques de nouveaux partenaires."],
  "candidats connus": ["Candidats connus", ""],
  "découverts": ["Découverts", ""],
  "proposés": ["Proposés", ""],
  "acceptés": ["Acceptés", ""],
  "terminé": ["Terminé", ""],
  "terminés": ["Terminés", ""],
  "mis en retrait": ["Mis en retrait", "Partenaires dont les fragments sont replacés ailleurs (score trop bas)."],
  "partenaires visés": ["Partenaires visés", ""],
  "liste noire": ["Liste noire", "Nœuds exclus après une fraude prouvée."],
  "depuis": ["Depuis", ""],
  "motif": ["Motif", ""],
  "fraudes": ["Fraudes", ""],

  // ---- Volumes
  "volumes": ["Volumes", "Disques ou dossiers où ce Nœud range les blocs."],
  "volume": ["Volume", ""],
  "volume_id": ["Numéro", ""],
  "mount_path": ["Chemin", ""],
  "chemin": ["Chemin", ""],
  "nouveau chemin": ["Nouveau chemin", ""],
  "max_capacity_bytes": ["Capacité", ""],
  "capacité (Go)": ["Capacité (Gio)", ""],
  "nouvelle capacité (Go)": ["Nouvelle capacité (Gio)", ""],
  "capacité (octets)": ["Capacité", ""],
  "slots libres (octets)": ["Libre dans les conteneurs", "Place libre dans les fichiers déjà créés sur le disque (réutilisable sans agrandir)."],
  "% occupé": ["Occupé (%)", ""],
  "action": ["Action", ""],
  "date": ["Date", ""],
  "effacer et réutiliser": ["Effacer et réutiliser", "Supprime les seules données S3m de ce disque (jamais un formatage)."],
  "modification": ["Modification", ""],
  "nº": ["Nº", ""],
  "retenus": ["Retenus", ""],
  "supprimés": ["Supprimés", ""],
  "déjà présents": ["Déjà présents", ""],
  "testés": ["Testés", ""],

  // ---- Stockage et protection
  "dispersion": ["Dispersion", "Calcul de la parité et placement chez les partenaires."],
  "dernier cycle": ["Dernier cycle", ""],
  "blocs en attente": ["Blocs en attente", "Blocs reçus pas encore protégés par de la parité."],
  "stripes": ["Groupes de blocs", ""],
  "stripes dispersés": ["Groupes protégés", "Groupes de blocs dont la parité est placée chez les partenaires."],
  "stripes d'index": ["Groupes d'index", ""],
  "fragments placés": ["Fragments placés", ""],
  "en attente de partenaires": ["En attente de partenaires", "Pas assez de partenaires pour placer la parité."],
  "partenaires requis par stripe": ["Partenaires requis par groupe", ""],
  "coef": ["Coefficient de parité", ""],
  "contrôles et réparation": ["Contrôles et réparation", "Vérification des partenaires et des blocs locaux, réparation automatique."],
  "challenges réussis": ["Contrôles réussis", ""],
  "challenges sans réponse": ["Contrôles sans réponse", ""],
  "challengés": ["Contrôlés", ""],
  "réussis": ["Réussis", ""],
  "sans réponse": ["Sans réponse", ""],
  "dernier scrubbing": ["Dernière vérification des blocs", "Relecture complète des blocs locaux pour détecter la corruption."],
  "blocs locaux réparés": ["Blocs locaux réparés", ""],
  "blocs reconstruits": ["Blocs reconstruits", ""],
  "fragments replacés": ["Fragments replacés", ""],
  "fragments libérés": ["Fragments libérés", ""],
  "fragments à purger": ["Fragments à purger", ""],
  "purge à venir": ["Purge à venir", ""],
  "purge échue": ["Purge échue", ""],
  "dernière analyse de volatilité": ["Dernière analyse de disponibilité", ""],
  "snapshot du nœud": ["Sauvegarde du Nœud", "Sauvegarde chiffrée de l'état du Nœud chez ses partenaires, restaurable avec sa phrase de récupération."],
  "dernier snapshot": ["Dernière sauvegarde", ""],
  "publié dans l'entrée Node": ["Publiée dans l'annuaire", ""],
  "restauration": ["Restauration", ""],
  "restauration au démarrage": ["Restauration au démarrage", ""],

  // ---- Espace de secours (Nœud)
  "espace de secours": ["Espace de secours", "Place réservée à d'autres utilisateurs dont le Nœud est momentanément injoignable."],
  "utilisateurs accueillis": ["Utilisateurs accueillis", "En cours / au plus."],
  "utilisateurs accueillis au plus": ["Utilisateurs accueillis au plus", "0 pour ne rien accueillir."],
  "espace par utilisateur (Gio)": ["Espace par utilisateur (Gio)", ""],
  "espace réservé (octets)": ["Espace réservé", "Utilisateurs au plus × espace par utilisateur."],
  "espace occupé (octets)": ["Espace occupé", ""],
  "plafond par utilisateur (octets)": ["Plafond par utilisateur", ""],
  "déposants": ["Utilisateurs accueillis", ""],
  "déposant": ["Clé de secours", "Identifie l'utilisateur accueilli sans révéler son identité."],
  "dépôts oubliés purgés": ["Dépôts oubliés supprimés", "Dépôts jamais libérés, supprimés au bout de 6 mois."],
  "retour de ce Nœud : dernier contrôle": ["Retour de ce Nœud : dernier contrôle", "Recherche des fichiers déposés ailleurs par vos utilisateurs pendant une absence de ce Nœud."],
  "retour de ce Nœud : bilan": ["Retour de ce Nœud : bilan", ""],
  "entrées à intégrer": ["Dépôts à récupérer", ""],
  "blocs intégrés": ["Blocs récupérés", ""],
  "blocs refusés (quota)": ["Blocs refusés (quota)", ""],
  "blocs introuvables (nouvel essai)": ["Blocs introuvables", "Nouvel essai automatique plus tard."],

  // ---- Réseau
  "traversée de NAT": ["Accès depuis Internet", "Comment les autres Nœuds joignent celui-ci malgré la box."],
  "joignabilité": ["Joignabilité", "Public : joignable directement ; derrière un NAT : via la box ou un relais."],
  "box (UPnP)": ["Box (UPnP)", "Ouverture automatique du port sur la box."],
  "adresse publique de la box": ["Adresse publique de la box", "Adresse Internet de votre box ; sert aussi à placer sur la carte les appareils du réseau local."],
  "adresses externes confirmées": ["Adresses directes", "Adresses Internet où ce Nœud est joignable directement."],
  "adresses via relais": ["Adresses via relais", "Adresses passant par un autre Nœud, quand l'accès direct est impossible."],
  "perçages réussis": ["Connexions directes établies", "Connexions directes obtenues malgré le NAT (perçage)."],
  "perçages échoués": ["Connexions directes échouées", ""],
  "circuits relayés pour d'autres": ["Relais rendus", "Connexions relayées pour d'autres Nœuds."],
  "écoute": ["Écoute", "Adresses locales où le Nœud attend les connexions."],
  "adresse annoncée": ["Adresse annoncée", ""],
  "adresses publiées": ["Adresses publiées", ""],
  "annuaire (entrée Node)": ["Annuaire (entrée du Nœud)", "Entrée de ce Nœud dans l'annuaire distribué : permet aux autres de le trouver."],
  "dernière publication": ["Dernière publication", ""],
  "publications": ["Publications", ""],
  "prochaine republication": ["Prochaine republication", ""],
  "DHT": ["Annuaire (DHT)", ""],
  "échange de blocs": ["Échange de blocs", ""],
  "republication DHT": ["Republication dans l'annuaire", "Les entrées de l'annuaire expirent : elles doivent être republiées au moins tous les 30 jours."],
  "taux de republication (%)": ["Taux de republication (%)", "Part des entrées republiées dans le délai."],
  "entrées gérées": ["Entrées gérées", ""],
  "à jour": ["À jour", ""],
  "à republier": ["À republier", ""],
  "en retard ou jamais publiées": ["En retard ou jamais publiées", ""],
  "entrée": ["Entrée", ""],
  "géolocalisation": ["Géolocalisation", "Base locale qui situe les adresses IP sur la carte (DB-IP, CC BY 4.0)."],
  "dernière mise à jour": ["Dernière mise à jour", ""],
  "active": ["Active", ""],
  "activé": ["Activé", ""],
  "activée": ["Activée", ""],

  // ---- Administration, configuration, diagnostic
  "administration à distance": ["Administration à distance", "Accès au tableau de bord de ce Nœud depuis le connecteur, protégé par un code 2FA."],
  "QR code 2FA": ["QR code 2FA", "À scanner avec votre application d'authentification."],
  "série du 2FA": ["Série du 2FA", "Augmente à chaque régénération du 2FA."],
  "clé": ["Clé", ""],
  "paramètres": ["Paramètres", ""],
  "en attente de redémarrage": ["En attente de redémarrage", "Réglages enregistrés qui s'appliqueront au prochain démarrage."],
  "migration": ["Migration", "Transfert vers un nouveau Nœud après une perte ou une compromission."],
  "anciens node_id couverts": ["Anciens identifiants couverts", ""],
  "délégations reçues": ["Délégations reçues", ""],
  "pointeurs de migration connus": ["Pointeurs de migration connus", ""],
  "événements récents": ["Événements récents", ""],
  "instant": ["Instant", ""],
  "heure (s)": ["Heure", ""],
  // Canal Nœud ↔ Utilisateurs
  "messages des utilisateurs": ["Messages des utilisateurs", "Messages reçus de vos utilisateurs, conservés 30 jours."],
  "messages envoyés": ["Messages envoyés", "Messages et alertes envoyés à vos utilisateurs, conservés 30 jours."],
  "clé d'annonce": ["Clé d'annonce", "Clé séparée de la phrase de récupération : elle seule peut signer une alerte de compromission que vos utilisateurs croiront."],
  "clé publique": ["Clé publique", "Partie publique, publiée dans l'annuaire ; la phrase de 24 mots n'est pas conservée par le Nœud."],
  "alerte dans l'annuaire": ["Alerte dans l'annuaire", "Copie de la dernière alerte, lisible même si ce Nœud est éteint."],
  "sorte": ["Sorte", "Information (signée par le Nœud) ou alerte (signée par la clé d'annonce)."],
  "envoyé le": ["Envoyé le", ""],
  "reçu le": ["Reçu le", ""],
  "émise le": ["Émise le", ""],
  "message": ["Message", ""],
  "nœud de remplacement": ["Nœud de remplacement", "Identifiant du Nœud vers lequel se rattacher."],
  "phrase d'annonce": ["Phrase d'annonce", "Les 24 mots remis à la création de la clé d'annonce."],
  "alerte du nœud": ["Alerte du Nœud", "Avertissement de compromission signé par la clé d'annonce de votre Nœud."],
  "messages du nœud": ["Messages du Nœud", "Messages de l'opérateur de votre Nœud, vérifiés."],
  "messages envoyés au nœud": ["Messages envoyés au Nœud", ""],
  "clé d'annonce du nœud": ["Clé d'annonce du Nœud", "Retenue au premier contact : une autre clé publiée ensuite est ignorée."],
  "acquittée": ["Acquittée", ""],
  "n°": ["N°", "Numéro du message, à reprendre pour le supprimer."],
  // Pseudos et empreintes
  "nom": ["Nom", "Nom lisible suivi de l'empreinte : seule l'empreinte identifie avec certitude."],
  "empreinte": ["Empreinte", "12 caractères tirés de la clé publique, impossibles à imiter en pratique : comparez-les pour reconnaître une identité."],
  "nom publié par l'opérateur": ["Nom publié par l'opérateur", "Nom choisi par l'opérateur de ce Nœud, lu dans l'annuaire."],
  "pseudo": ["Pseudo", "Nom de cette identité, visible par vous seul."],
  "étiquette": ["Étiquette", "Nom donné à cet utilisateur, visible par vous seul."],
  "conduite à tenir": ["Conduite à tenir", ""],
  "pointeur de migration": ["Pointeur de migration", "Redirection automatique vers un autre Nœud, ignorée après une alerte."],
};

// Texte affiché et infobulle d'une clé.
function lab(k) {
  const e = LABELS[k];
  if (e) return { text: e[0], tip: e[1] || "" };
  const s = String(k).replace(/\s*\(octets\)$/i, "");
  return { text: s.charAt(0).toUpperCase() + s.slice(1), tip: "" };
}

// Élément portant un libellé, avec son infobulle (marquée « ⓘ »).
function labelEl(tag, k, cls, extraTip) {
  const { text, tip } = lab(k);
  const e = el(tag, text, cls);
  const t = extraTip || tip;
  if (t) {
    e.title = t;
    e.appendChild(el("span", " ⓘ", "tip"));
  }
  return e;
}

// ---------------------------------------------------------------- messages

function toast(message, kind = "ok", href) {
  let box = document.getElementById("toasts");
  if (!box) {
    box = el("div");
    box.id = "toasts";
    box.setAttribute("role", "status");
    box.setAttribute("aria-live", "polite");
    document.body.appendChild(box);
  }
  const t = el("div", message, "toast " + kind);
  if (href) {
    const a = el("a", " Ouvrir");
    a.href = href;
    a.target = "_blank";
    a.rel = "noopener";
    t.appendChild(a);
  }
  box.appendChild(t);
  requestAnimationFrame(() => t.classList.add("show"));
  setTimeout(() => {
    t.classList.remove("show");
    setTimeout(() => t.remove(), 300);
  }, kind === "error" || href ? 7000 : 3500);
}

// ---------------------------------------------------------------- actions

// Appel sans message : rend la réponse JSON, ou lève l'erreur du moteur.
async function callAction(nom, body) {
  const r = await fetch("/api/action/" + encodeURIComponent(nom), {
    method: "POST",
    headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(await r.text());
  return r.json().catch(() => ({}));
}

// Rend `true` si l'action a réussi.
async function runAction(nom, body, button, label) {
  let ok = false;
  if (button) button.disabled = true;
  try {
    const r = await fetch("/api/action/" + encodeURIComponent(nom), {
      method: "POST",
      headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (r.ok) {
      const res = await r.json().catch(() => ({}));
      // `ouvrir` : page à ouvrir (dashboard d'un Nœud administré à distance).
      const w = res.ouvrir ? window.open(res.ouvrir, "_blank", "noopener") : true;
      toast(res.message || (label ? `${label} : c'est fait` : "C'est fait"), "ok", w ? undefined : res.ouvrir);
      // `révéler` : secret à noter, affiché une seule fois dans un panneau.
      if (res["révéler"]) showReveal(res["révéler"]);
      ok = true;
      refresh();
    } else {
      toast(await r.text(), "error");
    }
  } catch (e) {
    toast("Connexion au moteur impossible", "error");
  } finally {
    if (button) button.disabled = false;
  }
  return ok;
}

// ---------------------------------------------------------------- panneaux

// Panneau modal : titre, croix de fermeture, contenu ; fermé par Échap.
function modal(title, closable = true) {
  const d = el("dialog", undefined, "panel");
  const head = el("div", undefined, "panel-head");
  head.appendChild(el("h2", title));
  const close = () => {
    d.close();
    d.remove();
  };
  if (closable) {
    const x = el("button", "✕", "small close");
    x.type = "button";
    x.title = "Fermer";
    x.addEventListener("click", close);
    head.appendChild(x);
  } else {
    d.addEventListener("cancel", (e) => e.preventDefault());
  }
  d.appendChild(head);
  document.body.appendChild(d);
  return { d, close };
}

// Panneau d'édition d'une ligne : formulaires préremplis ; fermé après une
// modification réussie.
// Panneau ouvert dont la description porte une `clé` : son contenu est
// redessiné à chaque mise à jour (ex. message supprimé), fermé s'il disparaît.
let livePanel = null;

function panelBody(p) {
  const box = el("div", undefined, "panel-body");
  // `contenu` : valeurs affichées (ex. le message ouvert), `message` en bloc.
  if (p["contenu"]) box.appendChild(render(p["contenu"], p["clé"] ? "panneau:" + p["clé"] : undefined));
  if (p["message"] !== undefined) box.appendChild(el("blockquote", p["message"], "message"));
  return box;
}

function findPanel(v, key) {
  if (v === null || typeof v !== "object") return null;
  if (!Array.isArray(v) && v["clé"] === key && "titre" in v) return v;
  for (const x of Array.isArray(v) ? v : Object.values(v)) {
    const f = findPanel(x, key);
    if (f) return f;
  }
  return null;
}

function refreshPanel(status) {
  if (!livePanel || !livePanel.d.open) return (livePanel = null);
  const p = findPanel(status, livePanel.key);
  if (!p) {
    livePanel.close();
    livePanel = null;
    return;
  }
  const json = JSON.stringify([p["contenu"], p["message"]]);
  if (json === livePanel.json) return;
  livePanel.json = json;
  const body = panelBody(p);
  livePanel.body.replaceWith(body);
  livePanel.body = body;
}

function openPanel(p) {
  const { d, close } = modal(p["titre"] || "Modifier");
  const texts = Array.isArray(p["texte"]) ? p["texte"] : p["texte"] ? [p["texte"]] : [];
  texts.forEach((t) => d.appendChild(el("p", t, "muted")));
  const body = panelBody(p);
  d.appendChild(body);
  if (p["clé"]) livePanel = { key: p["clé"], d, close, body, json: JSON.stringify([p["contenu"], p["message"]]) };
  (p["formulaires"] || []).forEach((a) => d.appendChild(actionForm(a, close)));
  d.showModal();
  // `ouverture` : action silencieuse à l'ouverture (ex. marquer lu).
  if (p["ouverture"]) callAction(p["ouverture"]["nom"], p["ouverture"]["valeurs"] || {}).then(refresh, () => {});
  const first = d.querySelector("textarea, input:not([type=hidden])");
  if (first) first.focus();
}

// Secret affiché une seule fois (24 mots en grille 6 × 4) et démarche.
function showReveal(r) {
  const { d, close } = modal(r["titre"] || "À noter", false);
  (r["texte"] || []).forEach((t, i) => d.appendChild(el("p", `${i + 1}. ${t}`)));
  if (r["24 mots"]) d.appendChild(wordGrid(r["24 mots"]));
  // `à copier` : texte à transmettre (lien, invitation), avec bouton de copie.
  if (r["à copier"]) {
    const t = el("textarea", undefined, "to-copy");
    t.readOnly = true;
    t.value = r["à copier"];
    const c = el("button", "Copier", "secondary");
    c.type = "button";
    c.addEventListener("click", async () => {
      t.select();
      try {
        await navigator.clipboard.writeText(t.value);
      } catch (_) {
        document.execCommand("copy");
      }
      toast("Copié dans le presse-papiers", "ok");
    });
    d.append(t, c);
  }
  const b = el("button", r["fermer"] || "Fermer");
  b.type = "button";
  b.addEventListener("click", () => {
    if (!r["24 mots"] || window.confirm("Avez-vous bien noté les 24 mots ? Ils ne seront plus affichés.")) close();
  });
  d.appendChild(b);
  d.showModal();
}

function cell(v) {
  if (v === null || v === undefined) return "—";
  if (v === true) return "Oui";
  if (v === false) return "Non";
  if (Array.isArray(v) && v.every((x) => x === null || typeof x !== "object")) return v.length ? v.join("\n") : "Aucun";
  if (typeof v === "object") return JSON.stringify(v);
  return cap(String(v));
}

// Texte du moteur : première lettre en majuscule (sauf identifiants hexadécimaux).
function cap(s) {
  if (/^[0-9a-f]{8,}/.test(s) || !/^[a-zàâçéèêëîïôûùüÿœ]/.test(s)) return s;
  return s.charAt(0).toUpperCase() + s.slice(1);
}

// Valeur lisible selon son libellé : tailles en octets, instants Unix.
function bytes(n) {
  const u = ["o", "Ko", "Mo", "Go", "To", "Po"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) {
    n /= 1024;
    i++;
  }
  return (i ? n.toFixed(n < 10 ? 1 : 0).replace(".", ",") : String(n)) + " " + u[i];
}

const DATE_KEY = /(dernier|dernière|expire|publiée le|prochaine|contact|heure|date|le$)/i;

function fmt(k, v) {
  if (typeof v === "number" && k) {
    if (/octets/i.test(k)) return bytes(v);
    if (v > 1.4e9 && v < 4.2e9 && DATE_KEY.test(k)) return new Date(v * 1000).toLocaleString("fr-FR");
  }
  return cell(v);
}

// Phrase de récupération : grille alignée de 6 lignes × 4 colonnes, numérotée.
function wordGrid(text) {
  const g = el("ol", undefined, "words");
  text.trim().split(/\s+/).forEach((w) => g.appendChild(el("li", w)));
  return g;
}

// QR code : SVG fourni par le moteur, affiché comme image (jamais inséré).
// Objet imbriqué : sous-tableau.
function valueNode(v, k) {
  if (/24 mots|phrase d'annonce/.test(k || "") && typeof v === "string" && v.trim().split(/\s+/).length === 24) return wordGrid(v);
  if (v !== null && typeof v === "object" && !(Array.isArray(v) && v.every((x) => x === null || typeof x !== "object"))) {
    return render(v);
  }
  if (typeof v === "string" && /^\s*(<\?xml[^>]*>\s*)?<svg[\s>]/.test(v)) {
    const i = el("img", undefined, "qr");
    i.src = "data:image/svg+xml;charset=utf-8," + encodeURIComponent(v);
    i.alt = "QR code";
    return i;
  }
  return document.createTextNode(fmt(k, v));
}

function rowActions(list) {
  const td = el("td", undefined, "row-actions");
  for (const a of list || []) {
    // `champs` : zones de saisie dans la ligne, envoyées avec `valeurs`.
    const inputs = (a["panneau"] ? [] : a["champs"] || []).map((name) => {
      const i = el("input", undefined, "row-input");
      i.name = name;
      i.autocomplete = "off";
      i.placeholder = lab(name).text;
      i.title = lab(name).tip || lab(name).text;
      td.appendChild(i);
      return i;
    });
    const b = el("button", a["libellé"], "small" + (a["style"] ? " " + a["style"] : ""));
    b.type = "button";
    // `panneau` : le bouton ouvre un panneau (formulaires) ; `confirmer` :
    // confirmation avant l'envoi.
    b.addEventListener("click", (ev) => {
      ev.stopPropagation();
      if (a["panneau"]) return openPanel(a["panneau"]);
      if (a["confirmer"] && !window.confirm(a["confirmer"])) return;
      const v = Object.assign({}, a["valeurs"] || {});
      inputs.forEach((i) => (v[i.name] = i.value));
      runAction(a["nom"], v, b, a["libellé"]);
    });
    td.appendChild(b);
  }
  return td;
}

// Tableaux : filtre, tri, 10 / 50 / 100 lignes par page (ou un nombre
// saisi), export CSV (séparateur « ; », Excel). Une ligne qui porte
// `_ouvrir` s'ouvre dans un panneau au clic.
const PAGE_SIZES = [10, 50, 100];
const tableState = {};
const HIDDEN_COLS = new Set(["_actions", "_ouvrir", "_gras"]);

function csvOf(cols, rows) {
  const q = (s) => '"' + String(s).replace(/"/g, '""') + '"';
  return [cols.map((c) => q(lab(c).text)).join(";"), ...rows.map((o) => cols.map((c) => q(fmt(c, o[c]))).join(";"))].join("\r\n");
}

function download(name, text) {
  const a = el("a");
  a.href = URL.createObjectURL(new Blob(["﻿" + text], { type: "text/csv;charset=utf-8" }));
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

function render(value, key) {
  if (Array.isArray(value)) {
    if (value.length === 0) return el("p", "Aucun", "empty");
    if (typeof value[0] !== "object" || value[0] === null) {
      const ul = el("ul");
      value.forEach((v) => ul.appendChild(el("li", cell(v))));
      return ul;
    }
    const cols = [...new Set(value.flatMap((o) => Object.keys(o)))].filter((c) => !HIDDEN_COLS.has(c));
    const withActions = value.some((o) => o["_actions"]);
    const box = el("div", undefined, "table-box");
    const t = el("table");
    const head = t.createTHead().insertRow();
    const body = t.createTBody();
    // Tri et page conservés d'un rafraîchissement à l'autre (par section).
    const fresh = () => ({ sortCol: null, asc: true, page: 0, size: 10, filter: "" });
    const st = key ? (tableState[key] = tableState[key] || fresh()) : fresh();
    const foot = el("div", undefined, "table-foot");
    // Barre d'outils : filtre et nombre de lignes par page.
    const tools = el("div", undefined, "table-tools");
    if (value.length > 5) {
      const q = el("input", undefined, "table-filter");
      q.type = "search";
      q.placeholder = "Filtrer…";
      q.value = st.filter;
      q.dataset.filterKey = key || "";
      q.addEventListener("input", () => { st.filter = q.value; st.page = 0; fill(); });
      tools.appendChild(q);
    }
    if (value.length > PAGE_SIZES[0]) {
      const sizeBox = el("label", undefined, "page-size");
      sizeBox.appendChild(el("span", "Lignes par page"));
      const sel = el("select");
      [...PAGE_SIZES, "autre"].forEach((n) => {
        const o = el("option", n === "autre" ? "Autre…" : String(n));
        o.value = String(n);
        sel.appendChild(o);
      });
      sel.value = PAGE_SIZES.includes(st.size) ? String(st.size) : "autre";
      const other = el("input", undefined, "page-size-other");
      other.type = "number";
      other.min = "1";
      other.value = String(st.size);
      other.hidden = sel.value !== "autre";
      sel.addEventListener("change", () => {
        other.hidden = sel.value !== "autre";
        if (sel.value !== "autre") { st.size = Number(sel.value); st.page = 0; fill(); } else other.focus();
      });
      other.addEventListener("change", () => {
        const n = Math.max(1, Math.floor(Number(other.value) || 10));
        st.size = n; st.page = 0; fill();
      });
      sizeBox.append(sel, other);
      tools.appendChild(sizeBox);
    }
    const matches = (o) => {
      const f = st.filter.trim().toLowerCase();
      return !f || cols.some((c) => fmt(c, o[c]).toLowerCase().includes(f));
    };
    const sorted = () =>
      st.sortCol === null
        ? value.filter(matches)
        : value.filter(matches).sort((a, b) => {
            const x = a[st.sortCol], y = b[st.sortCol];
            const r = typeof x === "number" && typeof y === "number" ? x - y : cell(x).localeCompare(cell(y), "fr", { numeric: true });
            return st.asc ? r : -r;
          });
    const fill = () => {
      body.replaceChildren();
      const rows = sorted();
      const size = st.size || 10;
      const pages = Math.max(1, Math.ceil(rows.length / size));
      st.page = Math.min(st.page, pages - 1);
      if (!rows.length) {
        const r = body.insertRow();
        const c = el("td", st.filter ? "Aucune ligne ne correspond au filtre" : "Aucun", "empty");
        c.colSpan = cols.length + (withActions ? 1 : 0);
        r.appendChild(c);
      }
      rows.slice(st.page * size, (st.page + 1) * size).forEach((o) => {
        const r = body.insertRow();
        // `_gras` : ligne mise en évidence (ex. message non lu).
        if (o["_gras"]) r.classList.add("unread");
        if (o["_ouvrir"]) {
          r.classList.add("clickable");
          r.tabIndex = 0;
          r.title = "Ouvrir";
          const open = () => openPanel(o["_ouvrir"]);
          r.addEventListener("click", open);
          r.addEventListener("keydown", (e) => { if (e.key === "Enter") open(); });
        }
        cols.forEach((c) => {
          const text = fmt(c, o[c]);
          // Valeur longue (chemin, identifiant) : largeur minimale lisible.
          r.appendChild(el("td", text, text.length > 40 ? "long" : text.length <= 16 ? "short" : undefined));
        });
        if (withActions) r.appendChild(rowActions(o["_actions"]));
      });
      foot.replaceChildren();
      if (pages > 1) {
        const prev = el("button", "‹ Précédent", "small");
        const next = el("button", "Suivant ›", "small");
        prev.disabled = st.page === 0;
        next.disabled = st.page >= pages - 1;
        prev.addEventListener("click", () => { st.page--; fill(); });
        next.addEventListener("click", () => { st.page++; fill(); });
        foot.append(prev, el("span", `page ${st.page + 1} / ${pages} · ${rows.length} lignes`, "muted"), next);
      } else if (rows.length) {
        foot.append(el("span", `${rows.length} ligne${rows.length > 1 ? "s" : ""}`, "muted"));
      }
      if (key) {
        const csv = el("button", "Exporter en CSV", "small");
        csv.addEventListener("click", () => download(key + ".csv", csvOf(cols, sorted())));
        foot.append(csv);
      }
    };
    // En-tête : libellé, flèche de tri, infobulle (explication puis « cliquer pour trier »).
    const headText = (h) => {
      const c = h.dataset.col;
      h.textContent = lab(c).text + (st.sortCol === c ? (st.asc ? " ▲" : " ▼") : "");
      if (lab(c).tip) h.appendChild(el("span", " ⓘ", "tip"));
    };
    cols.forEach((c) => {
      const th = el("th");
      th.title = (lab(c).tip ? lab(c).tip + "\n" : "") + "Cliquer pour trier";
      th.style.cursor = "pointer";
      th.dataset.col = c;
      headText(th);
      th.addEventListener("click", () => {
        st.asc = st.sortCol === c ? !st.asc : true;
        st.sortCol = c;
        head.querySelectorAll("th[data-col]").forEach(headText);
        fill();
      });
      head.appendChild(th);
    });
    if (withActions) head.appendChild(el("th", ""));
    fill();
    if (tools.childNodes.length) box.append(tools);
    box.append(t, foot);
    return box;
  }
  if (value !== null && typeof value === "object" && ("_contenu" in value || "_formulaires" in value)) {
    const box = el("div", undefined, "section-body");
    if (value["_contenu"] !== undefined) box.appendChild(render(value["_contenu"], key));
    (value["_formulaires"] || []).forEach((a) => box.appendChild(cachedForm(a)));
    return box;
  }
  if (value !== null && typeof value === "object") {
    const t = el("table", undefined, "kv");
    Object.entries(value).forEach(([k, v]) => {
      const r = t.insertRow();
      r.appendChild(labelEl("th", k));
      const td = el("td");
      td.appendChild(valueNode(v, k));
      r.appendChild(td);
    });
    return t;
  }
  return el("p", cell(value));
}

// Formulaire : champs texte, nombre ou case à cocher, valeurs pré-remplies.
// `fixes` : valeurs envoyées sans champ visible (ligne éditée) ; `done` :
// appelé après succès (fermeture du panneau).
function actionForm(a, done) {
  // `panneau` : simple bouton qui ouvre le panneau (ex. « Ajouter un volume »).
  if (a["panneau"]) {
    const box = el("div", undefined, "form-button");
    const b = el("button", a["libellé"], a["style"]);
    b.type = "button";
    b.addEventListener("click", () => openPanel(a["panneau"]));
    box.appendChild(b);
    return box;
  }
  const f = el("form", undefined, (a["champs"] || []).length > 3 ? "form grid" : "form");
  const values = a["valeurs"] || {};
  const types = a["types"] || {};
  const help = a["aide"] || {};
  // `options` : choix d'un champ `choix` ([valeur, libellé]) ou suggestions
  // d'un champ `lettre` ; `visible_si` : { champ: [autre champ, valeur] }.
  const options = a["options"] || {};
  const visibleIf = a["visible_si"] || {};
  const labelsOf = {};
  // `libellés` : texte affiché d'un champ (le nom envoyé reste `champs`).
  const labels = a["libellés"] || {};
  if (a["titre"]) f.appendChild(el("h3", a["titre"]));
  // `texte` : explication (une ligne ou une liste) sous le titre.
  (Array.isArray(a["texte"]) ? a["texte"] : a["texte"] ? [a["texte"]] : []).forEach((t) =>
    f.appendChild(el("p", t, "form-text")));
  const inputs = (a["champs"] || []).map((name) => {
    const l = el("label");
    labelsOf[name] = l;
    const type = types[name];
    const i = type === "texte" ? el("textarea") : type === "choix" ? el("select") : el("input");
    i.name = name;
    i.autocomplete = "off";
    const text = labels[name] ? labels[name].charAt(0).toUpperCase() + labels[name].slice(1) : lab(name).text;
    const tip = help[name] || lab(name).tip;
    if (type === "texte") {
      i.rows = 5;
      if (values[name] !== undefined && values[name] !== null) i.value = String(values[name]);
      l.classList.add("wide");
      l.append(el("span", text), i);
      if (tip) l.firstChild.appendChild(el("span", " ⓘ", "tip"));
    } else if (type === "choix") {
      (options[name] || []).forEach(([v, t]) => {
        const o = el("option", t);
        o.value = v;
        i.appendChild(o);
      });
      if (values[name] !== undefined && values[name] !== null) i.value = String(values[name]);
      l.append(el("span", text), i);
      if (tip) l.firstChild.appendChild(el("span", " ⓘ", "tip"));
    } else if (type === "chemin") {
      // Chemin saisissable, ou choisi avec l'explorateur ; espace du disque.
      if (values[name] !== undefined && values[name] !== null) i.value = String(values[name]);
      const row = el("span", undefined, "path-row");
      const browse = el("button", "Parcourir…", "small secondary");
      browse.type = "button";
      // `explorateurs` : action d'exploration du champ (par défaut, disque local).
      const explorer = (a["explorateurs"] || {})[name] || "fs_browse";
      const space = el("span", "", "muted path-space");
      const showSpace = async () => {
        if (!i.value.trim() || explorer !== "fs_browse") { space.textContent = ""; return; }
        try {
          const r = await callAction("fs_browse", { chemin: i.value.trim(), "espace seul": true });
          space.textContent = spaceText(r["données"] && r["données"]["espace"]);
        } catch (_) {
          space.textContent = "";
        }
      };
      browse.addEventListener("click", () => openBrowser(i.value.trim(), (p) => { i.value = p; showSpace(); }, explorer));
      i.addEventListener("change", showSpace);
      row.append(i, browse);
      l.classList.add("wide");
      l.append(el("span", text), row, space);
      if (tip) l.firstChild.appendChild(el("span", " ⓘ", "tip"));
      showSpace();
    } else if (type === "lettre") {
      // Lettre saisissable, avec les lettres libres en suggestion.
      const list = el("datalist");
      list.id = "dl-" + Math.random().toString(36).slice(2);
      (options[name] || []).forEach((v) => {
        const o = el("option");
        o.value = Array.isArray(v) ? v[0] : v;
        list.appendChild(o);
      });
      i.setAttribute("list", list.id);
      i.classList.add("short-input");
      if (values[name] !== undefined && values[name] !== null) i.value = String(values[name]);
      l.append(el("span", text), i, list);
      if (tip) l.firstChild.appendChild(el("span", " ⓘ", "tip"));
    } else if (type === "bool") {
      i.type = "checkbox";
      i.checked = values[name] === true;
      l.classList.add("check");
      l.append(i, el("span", text));
      if (tip) l.lastChild.appendChild(el("span", " ⓘ", "tip"));
    } else {
      if (types[name] === "number") i.type = "number";
      if (values[name] !== undefined && values[name] !== null) i.value = String(values[name]);
      l.append(el("span", text), i);
      if (tip) l.firstChild.appendChild(el("span", " ⓘ", "tip"));
    }
    if (tip) l.title = tip;
    f.appendChild(l);
    return i;
  });
  // Visibilité conditionnelle des champs.
  const sync = () => {
    Object.entries(visibleIf).forEach(([name, [other, want]]) => {
      const o = inputs.find((x) => x.name === other);
      if (labelsOf[name] && o) labelsOf[name].hidden = o.value !== want;
    });
  };
  inputs.forEach((x) => x.addEventListener("change", sync));
  sync();
  const b = el("button", a["libellé"], a["style"]);
  b.type = "submit";
  f.appendChild(b);
  f.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const body = Object.assign({}, a["fixes"] || {}, a["valeurs"] && !(a["champs"] || []).length ? a["valeurs"] : {});
    inputs
      .filter((i) => !(labelsOf[i.name] && labelsOf[i.name].hidden))
      .forEach((i) => (body[i.name] = i.type === "checkbox" ? i.checked : i.value.trim()));
    // `confirmer` : fenêtre de confirmation avant l'envoi.
    if (a["confirmer"] && !window.confirm(a["confirmer"])) return;
    const send = () =>
      runAction(a["nom"], body, b, a["libellé"]).then((ok) => {
        if (!ok) return;
        // Zone de texte vidée : le même message ne part pas deux fois.
        f.querySelectorAll("textarea").forEach((t) => (t.value = ""));
        if (done) done();
      });
    // `différer` : envoi après n secondes, annulable.
    const delay = Number(a["différer"] || 0);
    if (!delay) return send();
    const fields = [...f.querySelectorAll("input, textarea, select")];
    fields.forEach((x) => (x.disabled = true));
    b.hidden = true;
    const bar = el("span", undefined, "send-delay");
    const info = el("span", "", "muted");
    const cancel = el("button", "Annuler l'envoi", "secondary");
    cancel.type = "button";
    bar.append(info, cancel);
    f.appendChild(bar);
    let left = delay;
    const tick = () => (info.textContent = `Envoi dans ${left} s…`);
    tick();
    const timer = setInterval(() => {
      left -= 1;
      if (left > 0) return tick();
      clearInterval(timer);
      bar.remove();
      b.hidden = false;
      fields.forEach((x) => (x.disabled = false));
      send();
    }, 1000);
    cancel.addEventListener("click", () => {
      clearInterval(timer);
      bar.remove();
      b.hidden = false;
      fields.forEach((x) => (x.disabled = false));
      toast("Envoi annulé", "ok");
    });
  });
  return f;
}

// Formulaire d'une section : le même élément est réutilisé tant que sa
// description ne change pas (saisie et focus conservés).
let formCache = new Map();
let formCacheNext = new Map();
function cachedForm(a) {
  const k = JSON.stringify(a);
  const f = formCache.get(k) || actionForm(a);
  formCacheNext.set(k, f);
  return f;
}

// --------------------------------------------------------- explorateur

function spaceText(e) {
  if (!e || !e["total (octets)"]) return "";
  const t = e["total (octets)"], f = e["disponible (octets)"];
  return `Espace : ${bytes(f)} disponibles sur ${bytes(t)} (${Math.round((f * 100) / t)} % restant)`;
}

// Choix d'un dossier : racines (disques, points de montage), dossier parent,
// sous-dossiers, création d'un dossier, chemin saisissable ; espace affiché.
function openBrowser(start, pick, explorer = "fs_browse") {
  const { d, close } = modal("Choisir un dossier");
  const bar = el("form", undefined, "browser-bar");
  const path = el("input");
  path.value = start || "";
  path.placeholder = "Chemin du dossier";
  const go = el("button", "Aller", "small");
  go.type = "submit";
  bar.append(path, go);
  const roots = el("div", undefined, "browser-roots");
  const space = el("p", "", "muted");
  const list = el("ul", undefined, "browser-list");
  const mk = el("form", undefined, "browser-new");
  const name = el("input");
  name.placeholder = "Nom du nouveau dossier";
  const mkb = el("button", "Créer le dossier", "small secondary");
  mkb.type = "submit";
  mk.append(name, mkb);
  const choose = el("button", "Choisir ce dossier");
  choose.type = "button";
  const err = el("p", "", "error");
  d.append(bar, roots, space, list, mk, err, choose);
  let current = "";
  const load = async (p) => {
    err.textContent = "";
    try {
      const r = (await callAction(explorer, { chemin: p }))["données"] || {};
      mk.hidden = r["création"] === false;
      current = r["chemin"] || "";
      path.value = current;
      space.textContent = spaceText(r["espace"]);
      roots.replaceChildren();
      (r["racines"] || []).forEach((x) => {
        const b = el("button", x, "small secondary");
        b.type = "button";
        b.addEventListener("click", () => load(x));
        roots.appendChild(b);
      });
      list.replaceChildren();
      if (r["parent"]) {
        const li = el("li", "⬑ Dossier parent", "up");
        li.tabIndex = 0;
        li.addEventListener("click", () => load(r["parent"]));
        list.appendChild(li);
      }
      (r["dossiers"] || []).forEach((n) => {
        const li = el("li", "📁 " + n);
        li.tabIndex = 0;
        li.addEventListener("click", () => load(r["séparateur"] ? current.replace(/[\\/]$/, "") + r["séparateur"] + n : n));
        li.addEventListener("keydown", (e) => { if (e.key === "Enter") li.click(); });
        list.appendChild(li);
      });
      // `fichiers` : un clic choisit le fichier (ex. élément à partager).
      (r["fichiers"] || []).forEach((n) => {
        const li = el("li", "📄 " + n, "file");
        li.tabIndex = 0;
        li.addEventListener("click", () => {
          pick(current.replace(/[\/]$/, "") + (r["séparateur"] || "/") + n);
          close();
        });
        li.addEventListener("keydown", (e) => { if (e.key === "Enter") li.click(); });
        list.appendChild(li);
      });
      if (!(r["dossiers"] || []).length && !(r["fichiers"] || []).length) list.appendChild(el("li", "Aucun sous-dossier", "empty"));
      choose.disabled = !current;
    } catch (e) {
      err.textContent = e.message;
    }
  };
  bar.addEventListener("submit", (e) => { e.preventDefault(); load(path.value.trim()); });
  mk.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!name.value.trim()) return;
    try {
      const r = await callAction("fs_mkdir", { chemin: current, nom: name.value.trim() });
      name.value = "";
      load((r["données"] || {})["chemin"] || current);
    } catch (x) {
      err.textContent = x.message;
    }
  });
  choose.addEventListener("click", () => { pick(current); close(); });
  d.showModal();
  load(start || "");
}

// --------------------------------------------------------------- affichage

// Écrans : le moteur décrit `pages` (sections et actions de chacune) et
// `résumé` (indicateurs de la vue d'ensemble). Sans `pages`, un seul écran.
const RESERVED = new Set(["titre", "actions", "carte", "pages", "résumé", "à signaler"]);
// `à signaler` : message affiché une fois, au premier chargement.
let signaled = false;
let actionsKey = "";
let shownPage = null;
const tabState = {};
let lastStatus = null;
let page = null;

function pagesOf(status) {
  const all = Object.keys(status).filter((k) => !RESERVED.has(k));
  const pages = status["pages"];
  if (!Array.isArray(pages) || pages.length === 0) {
    return [{ id: "_", titre: "", sections: all, actions: null, carte: true }];
  }
  // La carte n'existe que sur le Nœud lui-même (pas à distance).
  const out = pages
    .filter((p) => p["cadre"] !== "map.html" || status["carte"])
    .map((p) => ({ ...p, sections: [...(p.sections || [])] }));
  // Ce qu'aucun écran ne cite va dans l'écran « autres » (rien ne se perd).
  // `onglets de sections` : [{ titre, sections }], sections réparties en onglets.
  const tabbed = (p) => (p["onglets de sections"] || []).flatMap((t) => t.sections || []);
  const used = new Set(out.flatMap((p) => [...p.sections, ...tabbed(p)]));
  const other = out.find((p) => p["autres"]) || out[out.length - 1];
  all.filter((k) => !used.has(k)).forEach((k) => other.sections.push(k));
  const named = new Set(out.flatMap((p) => p.actions || []));
  other.extra = (status["actions"] || []).filter((a) => !named.has(a["nom"])).map((a) => a["nom"]);
  return out;
}

function go(id) {
  page = id;
  try {
    sessionStorage.setItem("s3m-page", id);
  } catch (e) {
    /* stockage indisponible : sans effet */
  }
  window.scrollTo(0, 0);
  if (lastStatus) show(lastStatus);
}

function menu(pages) {
  let nav = document.getElementById("menu");
  if (pages.length < 2) {
    if (nav) nav.remove();
    document.body.classList.remove("with-menu");
    return;
  }
  document.body.classList.add("with-menu");
  if (!nav) {
    nav = el("nav");
    nav.id = "menu";
    nav.setAttribute("aria-label", "Écrans");
    document.body.insertBefore(nav, main);
  }
  const key = pages.map((p) => p.id + ":" + p.titre).join("|") + "#" + page;
  if (nav.dataset.key === key) return;
  nav.dataset.key = key;
  nav.replaceChildren();
  pages.forEach((p) => {
    const b = el("button", p.titre, p.id === page ? "active" : undefined);
    b.type = "button";
    if (p.id === page) b.setAttribute("aria-current", "page");
    b.addEventListener("click", () => go(p.id));
    nav.appendChild(b);
  });
}

function cards(list) {
  const box = el("div", undefined, "cards");
  list.forEach((c) => {
    const d = el(c["page"] ? "button" : "div", undefined, "card " + (c["état"] || "neutre"));
    if (c["page"]) {
      d.type = "button";
      d.addEventListener("click", () => go(c["page"]));
    }
    d.appendChild(el("span", c["libellé"], "card-label"));
    d.appendChild(el("span", c["unité"] === "octets" ? bytes(c["valeur"] || 0) : cell(c["valeur"]), "card-value"));
    if (c["détail"]) d.appendChild(el("span", c["détail"], "card-detail"));
    box.appendChild(d);
  });
  return box;
}

function show(status) {
  lastStatus = status;
  refreshPanel(status);
  if (!signaled) {
    signaled = true;
    if (status["à signaler"]) toast(status["à signaler"], "ok");
  }
  // Pas de redessin pendant qu'un panneau est ouvert, ni de perte de saisie
  // dans un filtre de tableau.
  const focused = document.activeElement;
  const filterKey = focused && focused.dataset ? focused.dataset.filterKey : undefined;
  const caret = filterKey !== undefined ? focused.selectionStart : 0;
  setTimeout(() => {
    if (filterKey === undefined) return;
    const q = [...document.querySelectorAll("input.table-filter")].find((x) => x.dataset.filterKey === filterKey);
    if (q) { q.focus(); q.setSelectionRange(caret, caret); }
  }, 0);
  document.getElementById("title").textContent = status["titre"] || "S3m";
  document.title = status["titre"] || "S3m";
  const pages = pagesOf(status);
  if (!page || !pages.some((p) => p.id === page)) {
    let saved = null;
    try {
      saved = sessionStorage.getItem("s3m-page");
    } catch (e) {
      /* stockage indisponible */
    }
    const want = linkedPage || saved;
    page = pages.some((p) => p.id === want) ? want : pages[0].id;
  }
  menu(pages);
  const p = pages.find((x) => x.id === page);
  const wanted = p.actions === null ? null : [...(p.actions || []), ...(p.extra || [])];
  const pageActions = (status["actions"] || []).filter((a) => wanted === null || wanted.includes(a["nom"]));
  // `mise_en_avant` : en bandeau en haut de l'écran (ex. modifications en
  // attente à appliquer), pas avec les autres actions.
  const highlighted = pageActions.filter((a) => a["mise_en_avant"]);
  const actions = pageActions.filter((a) => !a["mise_en_avant"]);
  // Défilement horizontal des sections conservé d'un rafraîchissement à l'autre.
  const scrolls = {};
  main.querySelectorAll("[data-scroll-key]").forEach((x) => (scrolls[x.dataset.scrollKey] = x.scrollLeft));
  // Défilement vertical : la page ne remonte pas pendant le redessin.
  const pageY = window.scrollY;
  main.style.minHeight = main.offsetHeight + "px";
  // Les formulaires ne sont reconstruits que s'ils changent, et restent dans
  // la page entre deux rafraîchissements : saisie et focus préservés.
  const key = page + JSON.stringify(actions);
  let keep = document.getElementById("actions");
  if (keep && key !== actionsKey) {
    keep.remove();
    keep = null;
  }
  // Écran intégré (`cadre`, ex. la carte) : gardé entre deux rafraîchissements
  // (zoom et position conservés).
  let frame = document.getElementById("frame");
  if (frame && frame.dataset.page !== page) {
    frame.remove();
    frame = null;
  }
  [...main.children].forEach((c) => c !== keep && c !== frame && c.remove());
  const frag = document.createDocumentFragment();
  if (pages.length > 1) frag.appendChild(el("h2", p.titre, "page-title"));
  if (highlighted.length) {
    const b = el("section", undefined, "callout");
    const row = el("div", undefined, "callout-forms");
    highlighted.forEach((a) => row.appendChild(actionForm(a)));
    b.appendChild(row);
    frag.appendChild(b);
  }
  if (p["résumé"] && Array.isArray(status["résumé"])) frag.appendChild(cards(status["résumé"]));
  const mapPage = pages.find((x) => x["cadre"] === "map.html");
  if (status["carte"] && p.carte) {
    const s = el("section");
    const b = el("button", "Ouvrir la carte du monde");
    b.addEventListener("click", () =>
      mapPage ? go(mapPage.id) : window.open("map.html#token=" + encodeURIComponent(token), "_blank", "noopener"),
    );
    s.appendChild(b);
    frag.appendChild(s);
  }
  if (p["cadre"] && !frame) {
    frame = el("iframe", undefined, "frame");
    frame.id = "frame";
    frame.dataset.page = page;
    frame.title = p.titre;
    frame.src = p["cadre"] + "#token=" + encodeURIComponent(token);
    main.appendChild(frame);
  }
  if (p["cadre"]) {
    const full = el("a", "Ouvrir en plein écran", "frame-link");
    full.href = p["cadre"] + "#token=" + encodeURIComponent(token);
    full.target = "_blank";
    full.rel = "noopener";
    frag.appendChild(full);
  }
  formCacheNext = new Map();
  const section = (k, into) => {
    if (!(k in status)) return;
    const s = el("section");
    s.dataset.scrollKey = page + "/" + k;
    s.appendChild(labelEl("h2", k));
    s.appendChild(render(status[k], k));
    into.appendChild(s);
  };
  p.sections.forEach((k) => section(k, frag));
  // Onglets de sections ; l'onglet ouvert est retenu.
  const groups = p["onglets de sections"] || [];
  if (groups.length) {
    const tabs = el("div", undefined, "tabs");
    tabs.setAttribute("role", "tablist");
    const panes = groups.map((g) => {
      const pane = el("div");
      (g.sections || []).forEach((k) => section(k, pane));
      return pane;
    });
    const pick = (n) => {
      tabState[page + "#sections"] = n;
      [...tabs.children].forEach((b, j) => b.setAttribute("aria-selected", String(j === n)));
      panes.forEach((x, j) => (x.hidden = j !== n));
    };
    groups.forEach((g, n) => {
      const b = el("button", g.titre, "tab");
      b.type = "button";
      b.setAttribute("role", "tab");
      b.addEventListener("click", () => pick(n));
      tabs.appendChild(b);
    });
    frag.appendChild(tabs);
    panes.forEach((x) => frag.appendChild(x));
    pick(Math.min(tabState[page + "#sections"] || 0, groups.length - 1));
  }
  formCache = formCacheNext;
  main.insertBefore(frag, frame || keep);
  main.querySelectorAll("[data-scroll-key]").forEach((x) => {
    if (scrolls[x.dataset.scrollKey]) x.scrollLeft = scrolls[x.dataset.scrollKey];
  });
  main.style.minHeight = "";
  if (page === shownPage) window.scrollTo(0, pageY);
  shownPage = page;
  if (!keep && actions.length) {
    const s = el("section");
    s.id = "actions";
    s.appendChild(el("h2", "Actions"));
    if (p["onglets"] && actions.length > 1) {
      // Une sous-section par onglet ; l'onglet ouvert est retenu.
      const tabs = el("div", undefined, "tabs");
      tabs.setAttribute("role", "tablist");
      const panes = actions.map((a) => {
        const pane = actionForm(a);
        pane.hidden = true;
        return pane;
      });
      const name = (a) => (a["titre"] || a["libellé"] || a["nom"]).replace(/^Configuration — /, "");
      const pick = (n) => {
        tabState[page] = n;
        [...tabs.children].forEach((b, j) => b.setAttribute("aria-selected", String(j === n)));
        panes.forEach((x, j) => (x.hidden = j !== n));
      };
      actions.forEach((a, n) => {
        const b = el("button", name(a), "tab");
        b.type = "button";
        b.setAttribute("role", "tab");
        b.addEventListener("click", () => pick(n));
        tabs.appendChild(b);
      });
      s.appendChild(tabs);
      panes.forEach((x) => {
        const h = x.querySelector("h3");
        if (h) h.remove();
        s.appendChild(x);
      });
      pick(Math.min(tabState[page] || 0, actions.length - 1));
    } else {
      actions.forEach((a) => s.appendChild(actionForm(a)));
    }
    main.appendChild(s);
    actionsKey = key;
  }
}

async function refresh() {
  const r = await fetch("/api/status", { headers: { Authorization: "Bearer " + token } });
  if (!r.ok) {
    live.textContent = "accès refusé : ouvrez une fois le tableau de bord depuis S3m (icône ou adresse affichée au démarrage)";
    live.className = "error";
    return;
  }
  show(await r.json());
}

function connect() {
  const ws = new WebSocket("ws://" + location.host + "/api/ws");
  ws.onopen = () => {
    ws.send(token);
    live.textContent = "en direct";
    live.className = "";
  };
  ws.onmessage = (m) => show(JSON.parse(m.data));
  ws.onclose = () => {
    live.textContent = "déconnecté — nouvelle tentative…";
    setTimeout(connect, 3000);
  };
}

refresh().then(connect);
