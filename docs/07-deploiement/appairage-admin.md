---
id: deploiement.appairage-admin
kind: narrative
title: "Identité temporaire, Appairage et Administration à distance du Nœud"
section: "§7.3"
status: draft
verified_by: []
---

# Identité temporaire, appairage et administration à distance

Fonctionnalité ajoutée le 2026-11-20. Un Nœud neuf démarre sans identité
définitive et peut être configuré depuis le Connecteur d'un autre ordinateur
du réseau local ; une fois configuré, il reste administrable à distance,
protégé par un code de double authentification (2FA).

## Identité temporaire {: #temporaire }

Au premier lancement (fichier de phrase de récupération absent), le Nœud tire
une paire Ed25519 **aléatoire, jamais écrite sur disque ni publiée**. Avec
elle il ne fait que servir son assistant : aucune entrée DHT
([`network.dht-directory`](../01-network-dht/dht-directory.md)), aucune VDF
([`network.vdf-identity`](../01-network-dht/vdf-identity.md)), aucun
partenariat, aucun Utilisateur, aucune donnée. Il s'annonce sur le réseau
local comme « à configurer »
([`network.bootstrap`](../01-network-dht/bootstrap.md#reseau-local)).

L'assistant propose deux choix :

- **Nouvelle identité** : phrase de récupération tirée au hasard, affichée
  sous forme de [code de récupération](../03-crypto/identity-derivation.md#code-de-recuperation)
  (QR code, texte et 24 mots) avec le QR code 2FA ; elle n'est écrite
  qu'après confirmation de l'opérateur, puis le Nœud démarre normalement
  (VDF, publication).
- **Identité existante** : saisie du code de récupération ou des 24 mots ;
  le Nœud démarre et se restaure depuis son snapshot
  ([`deploiement.disaster-recovery`](disaster-recovery.md#snapshot)).

Le passage à l'identité définitive ferme toutes les sessions temporaires ;
l'identité temporaire est oubliée.

Un Connecteur sans configuration (assistant de premier lancement,
[`deploiement.packaging`](packaging.md#barre-des-taches)) a lui aussi une
identité temporaire ; pour administrer un Nœud il utilise toujours une paire
libp2p jetable : ses clés d'Utilisateur ne donnent **aucun** droit sur un
Nœud ([`crypto.key-hierarchy`](../03-crypto/key-hierarchy.md)).

## Canal d'administration {: #canal }

libp2p (TCP, Noise, Yamux), protocole `/s3m/admin/1`, requête/réponse en
JSON UTF-8 (1 Mio au plus). Le Nœud l'écoute sur `admin_listen`
(par défaut `/ip4/0.0.0.0/tcp/4003`), avec son identité temporaire puis
définitive. Messages (une clé par message) :

| Requête | Réponse | Mode |
|---|---|---|
| `{"hello":{}}` | `{"hello":{"mode":"setup"\|"node","version":1}}` | tous |
| `{"pake_start":{"msg":hex}}` | `{"pake_reply":{"msg":hex}}` | temporaire |
| `{"pake_confirm":{"mac":hex}}` | `{"session":{"token":hex,"mac":hex}}` | temporaire |
| `{"login":{"totp":"123456"}}` | `{"session":{"token":hex}}` | définitif |
| `{"call":{"token":hex,"op":"status"}}` | `{"result":…}` | tous |
| `{"call":{"token":hex,"op":"action","name":…,"body":{…}}}` | `{"result":…}` | tous |

Toute erreur : `{"error":"…"}`. `status` et `action` sont exactement ceux de
l'[API locale](packaging.md#api-locale) (la carte n'est pas exposée). Le
Connecteur présente le résultat dans un dashboard servi sur son propre
`127.0.0.1`, protégé par les mêmes règles que l'API locale.

**Sessions** : jeton aléatoire de 32 octets, lié au `PeerId` du client
(une requête d'un autre pair est refusée), expiré après 30 min
d'inactivité.

**Essais limités** : après 5 échecs (appairage ou 2FA), toute nouvelle
tentative est refusée pendant 1 min, durée doublée à chaque nouvel échec
jusqu'à 1 h ; un succès remet le compteur à zéro.

## Appairage (identité temporaire) {: #appairage }

Le Nœud temporaire affiche un **code d'appairage** de 8 caractères de
l'alphabet base32 (RFC 4648, présentation `XXXX-XXXX`, 40 bits), tiré à
chaque lancement, dans sa console, ses journaux et son dashboard local.
L'opérateur le saisit dans le Connecteur.

Le code n'est jamais transmis : les deux côtés exécutent un **SPAKE2**
symétrique (groupe Ed25519, mot de passe = code en majuscules sans tiret,
identité `"s3m/pairing/v1"`), qui donne une clé `K` sans permettre de
deviner le code hors ligne. Confirmation, liée aux deux pairs :

- `mac_client = HMAC-SHA256(K, "client" ‖ PeerId_Nœud ‖ PeerId_client)`,
  vérifié par le Nœud ;
- `mac_nœud = HMAC-SHA256(K, "node" ‖ PeerId_Nœud ‖ PeerId_client)`,
  vérifié par le Connecteur avant d'utiliser la session.

Un faux Nœud sans le code ne peut produire `mac_nœud` ; un relais
intermédiaire ne peut ni deviner le code ni réutiliser la confirmation.
Le code cesse d'être valable dès que l'identité définitive est choisie.

## Administration à distance (identité définitive) {: #administration }

Active si `remote_admin` (par défaut `true`). Seule authentification : un
code **TOTP** (RFC 6238 : HMAC-SHA1, pas de 30 s, 6 chiffres), dont le
secret est
[dérivé de `priv_node`](../03-crypto/symmetric-suite.md)
(`"admin-totp"`, numéro de série) — retrouvé après une restauration sans
nouvel enrôlement, mais **pas indépendant** de la phrase de récupération :
qui détient celle-ci détient aussi le 2FA. Le Nœud ne le stocke pas : il le
redérive de la clé qu'il détient déjà.

- Le QR code 2FA (URI `otpauth://totp/S3m:<8 premiers hex de node_id>?secret=<base32>&issuer=S3m&algorithm=SHA1&digits=6&period=30`)
  est distinct du code de récupération : ne jamais scanner ce dernier avec
  une application 2FA.
- Fenêtre d'acceptation ±1 pas ; un même pas n'est accepté qu'une fois.
- Téléphone perdu : « régénérer le 2FA » incrémente le numéro de série
  (`admin_totp_serial` de `node.json`) et ferme toutes les sessions.
  L'affichage du QR code 2FA et sa régénération ne sont possibles que
  depuis le dashboard local, jamais par le canal distant.
- Le Connecteur joint le `PeerId` **déjà connu** de son Nœud (sa
  configuration) : le Nœud est authentifié par libp2p avant tout envoi du
  code TOTP. L'adresse par défaut reprend l'IP du Nœud et le port 4003.

## Menaces couvertes

| Menace | Réponse |
|---|---|
| Voisin du réseau local qui revendique un Nœud neuf | code d'appairage requis, essais limités |
| Écoute du code d'appairage | jamais transmis (SPAKE2) |
| Faux Nœud « à configurer » | `mac_nœud` invérifiable sans le code |
| Vol d'un code TOTP en transit | Noise vers le `PeerId` attendu ; pas à usage unique |
| Téléphone 2FA perdu | régénération locale (numéro de série) |
| Phrase de récupération compromise | hors périmètre : 2FA compromis aussi ([`securite.incidents-compromissions`](../05-securite/incidents-compromissions.md)) |

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*
