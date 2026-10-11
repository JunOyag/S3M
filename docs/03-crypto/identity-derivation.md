---
id: crypto.identity-derivation
kind: narrative
title: "Dérivation des Identités — BIP-39 → SLIP-0010"
section: "§5.2, §7.1"
status: draft
verified_by: []
---

# Dérivation des Identités — BIP-39 → SLIP-0010

Toutes les identités asymétriques du protocole (`priv_user`/`pub_user`,
`priv_node`/`pub_node`, et la clé de secours du Nœud) dérivent d'une phrase
mnémonique BIP-39 selon un schéma de chemins fixe et entièrement durci.
Cette page est l'**unique** source de ce schéma ; chaque mécanisme qui en a
besoin y renvoie ([`crypto.key-hierarchy`](key-hierarchy.md),
[`deploiement.disaster-recovery`](../07-deploiement/disaster-recovery.md),
[`securite.incidents-compromissions`](../05-securite/incidents-compromissions.md)).

## Chaîne de dérivation

1. Phrase mnémonique BIP-39 → **seed de 64 octets** : PBKDF2-HMAC-SHA512,
   passphrase **vide par défaut** (standard BIP-39 — voir les avertissements
   plus bas).
2. Seed de 64 octets → **clé maître SLIP-0010** :
   `HMAC-SHA512(clé = "ed25519 seed", données = seed)` (SLIP-0010,
   courbe ed25519).
3. Chemins **entièrement durcis** — SLIP-0010 n'autorise que la dérivation
   durcie pour ed25519 :

```
m/0x703270'/<role>'/<index>'
```

`purpose' = 0x703270'` — « p2p » en ASCII (7 352 944 en décimal, indice
écrit en hexadécimal par choix : c'est une convention applicative, pas un
type de pièce ; l'indice durci sérialisé vaut `0x80703270`).

## Rôles

| Chemin | Identité | Usage |
|---|---|---|
| `m/0x703270'/0'/<index>'` | User — `priv_user` / `pub_user` | signature ; [`crypto.k-attach`](k-attach.md) ; entrée DHT User ([`network.dht-directory`](../01-network-dht/dht-directory.md)) |
| `m/0x703270'/1'/<index>'` | Node — `priv_node` / `pub_node` (`node_id` = `pub_node`) | signature ; [`crypto.k-attach`](k-attach.md) ; entrée DHT Node |
| `m/0x703270'/2'/<index>'` | Clé de secours du Node d'index `<index>'` — `priv_node_recovery` / `pub_node_recovery` | [`securite.incidents-compromissions`](../05-securite/incidents-compromissions.md) (`migration_pointer`) |
| `m/0x703270'/3'/version'` | Clé maîtresse — `master_key[version]` (`version` : `uint16`, compteur indépendant démarrant à 0) | [`crypto.master-key-chain`](master-key-chain.md) ; ne signe jamais, ne sert à aucun échange DH |

**Clé de secours en miroir** : la clé de secours d'une identité Node `i`
occupe l'index `i` du rôle `2'` — `m/0x703270'/2'/i'` accompagne
`m/0x703270'/1'/i'`. La compromission d'une clé de secours n'invalide donc
pas les autres identités Node dérivées de la même seed.

Aucun rôle au-delà de `0'` / `1'` / `2'` / `3'` n'est défini à ce jour.

## La clé privée SLIP-0010 est une graine Ed25519

La « clé privée » produite par SLIP-0010 (ed25519) **est** une graine de
32 octets au sens RFC 8032 — pas un scalaire étendu. La clé publique
correspondante se calcule par la dérivation Ed25519 standard (le SHA-512
interne est géré par la bibliothèque). C'est exactement la convention de
représentation déjà utilisée par [`crypto.k-attach`](k-attach.md) :
`priv_user` / `priv_node` en 32 octets, conversion vers X25519 par
`clamp(SHA-512(graine)[0..32])` — les deux coïncident, aucune traduction
n'est nécessaire entre le schéma de chemins et le reste du protocole.

## Règle d'index — deux cas de rotation distincts

Une rotation d'identité n'implique **pas** toujours une nouvelle seed. Deux
cas à distinguer :

1. **Fuite d'une clé dérivée (pas de la seed)** : nouvelle identité à
   l'index suivant (`<index>' + 1`) dans le rôle concerné ; un index fuité
   n'est **jamais** réutilisé. Côté Node, c'est le mécanisme du
   `migration_pointer` (§5.2, point 6 — voir
   [`securite.incidents-compromissions`](../05-securite/incidents-compromissions.md)) ;
   la règle s'applique identiquement côté User.
2. **Fuite de la seed** : incrémenter l'index ne protège de rien — un
   attaquant en possession de la seed dérive lui aussi l'index suivant. La
   seule parade est une **nouvelle phrase mnémonique** (donc une nouvelle
   seed, donc un arbre d'identités entièrement nouveau).

## Clé maîtresse — rôle `3'`

`master_key[version]` est la clé enfant SLIP-0010 ed25519 durcie au chemin
`m/0x703270'/3'/version'` — même seed, même passphrase que l'identité User
courante. `version` est un compteur **indépendant** de l'index d'identité,
démarre à 0, borné par `uint16`. Le rôle `3'` ne signe jamais et ne sert à
aucun échange DH.

Sans ce rôle dédié, l'« indépendance » mathématique promise par
[`crypto.master-key-chain`](master-key-chain.md) tomberait : si
`master_key` ne dépendait pas d'un compteur propre, incrémenter l'index
d'identité ne la changerait pas. Règles de rotation :

- rotation d'identité seule (clé dérivée fuitée, index + 1) : **pas** de
  nouvelle version ;
- nouvelle seed ou fuite de `master_key` elle-même : nouvelle version +
  re-wrap de la chaîne.

`master_key_chain` reste l'**unique** mécanisme de lecture des versions
antérieures (pas de re-dérivation depuis la seed pour lire l'historique).

## Découverte de l'index courant après perte totale

Après une perte totale, la seed seule (même avec la bonne passphrase) ne
désigne pas le bon `<index>'` — ni pour le User ni pour le Node. La
restauration à froid
([`network.bootstrap`](../01-network-dht/bootstrap.md), §2.2) et la
procédure complète
([`deploiement.disaster-recovery`](../07-deploiement/disaster-recovery.md))
reposent sur cette règle — **définie ici et nulle part ailleurs** :

1. Balayer les index croissants à partir de 0 dans le rôle concerné,
   dériver l'identité candidate et résoudre son entrée DHT.
2. Une entrée est **valide** si et seulement si : signature correcte,
   preuve VDF présente et valide, durée de vie non expirée.
3. L'index courant est le **plus haut index ayant une entrée valide** —
   pas de tri par date : une clé dérivée compromise permet de rafraîchir
   une ancienne entrée, mais pas d'en créer une à un index supérieur.
4. Arrêt après **20 index consécutifs sans entrée** — valeur configurable
   selon l'implémentation.
5. Avant de créer un nouvel index `k`, balayage préalable pour s'assurer
   qu'aucune entrée vivante n'y est déjà.
6. Si rien n'est trouvé : afficher « vérifier la passphrase » (voir les
   avertissements plus haut) plutôt que « compte inexistant ».

Côté User, la version de `master_key` se lit dans `master_key_chain`
(pas de balayage). Côté Node, seules les entrées de moins de 6 mois sont
découvrables (§3.9). **Limite documentée** : si toutes les entrées ont
expiré, un index compromis peut être retrouvé par erreur — recommander de
conserver l'index courant avec la sauvegarde de la phrase.

## Passphrase — deux avertissements

La passphrase BIP-39 (« 25ᵉ mot ») est optionnelle, **vide par défaut**.
Si elle est utilisée :

1. **Une mauvaise passphrase ne produit aucune erreur.** Elle dérive une
   identité valide mais différente : la restauration à froid
   ([`network.bootstrap`](../01-network-dht/bootstrap.md), §2.2) conclut
   simplement « aucune entrée trouvée » — avec l'apparence d'un compte qui
   n'a jamais existé.
2. **La passphrase n'est stockée nulle part.** La perdre revient à perdre
   l'identité, et l'accès à toutes les données qui en dérivent.

## Périmètre de ce schéma

Seules les identités asymétriques, la clé de secours et la clé maîtresse
passent par ce schéma. Les clés symétriques dérivées en aval de ces
identités — `K_self`
([`crypto.k-self`](k-self.md)), `K_node_self`
([`crypto.k-node-self`](k-node-self.md)), `sig_priv_dispersal`, … — ne
passent pas par lui : leur dérivation reste définie sur leurs pages
respectives.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->