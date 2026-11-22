---
id: network.traversee-nat
kind: narrative
title: "Traversée de NAT"
section: "§2"
status: draft
verified_by: []
---

# Traversée de NAT

Fonctionnalité ajoutée le 2026-11-20 (reportée par
[`network.bootstrap`](bootstrap.md)). Un Nœud installé derrière une box
domestique ou un pare-feu reste joignable par ses partenaires et ses
Connecteurs. Tous les mécanismes sont ceux de `libp2p` ; aucun serveur
STUN/TURN dédié n'est requis.

## Un seul point d'accès réseau par Nœud

La DHT ([`network.dht-directory`](dht-directory.md)) et l'échange de blocs
([`protocols.echange-blocs`](../04-protocols/echange-blocs.md)) partagent
une seule pile libp2p (même identité `pub_node`, mêmes ports) : TCP et
**QUIC** (UDP, même numéro de port), Noise, Yamux.

## Quatre mécanismes, du moins au plus coûteux

1. **UPnP / IGD** : le Nœud demande à la box la redirection de son port
   (TCP et UDP). Activé par défaut, désactivable (`upnp: false`). La
   recherche de la box part de l'adresse locale de la route par défaut
   (sinon, sur une machine à plusieurs cartes réseau — WSL, Hyper-V, VPN —
   elle peut sortir par une carte virtuelle et rester sans réponse) ; bail
   d'une heure renouvelé, nouvel essai toutes les 5 minutes en cas d'échec.
2. **Détection de joignabilité** (AutoNAT, Identify) : les pairs renvoient
   l'adresse publique observée et testent un rappel ; le Nœud se sait
   *public* ou *derrière un NAT*. Les adresses confirmées deviennent ses
   adresses externes.
3. **Relais** (circuit relay v2) : un Nœud derrière un NAT réserve une place
   chez au plus **2** Nœuds publics, de préférence ses partenaires, et
   annonce l'adresse `…/p2p/<relais>/p2p-circuit/p2p/<lui>`. Tout Nœud
   public assure ce service avec des limites prudentes : 16 réservations,
   10 min et 16 MiB par circuit (réglables). Le relais sert surtout à
   amorcer le point 4 ; un partenaire joint uniquement par relais est lent et
   son score de vitesse le reflète
   ([`protocols.partenariat-automatique`](../04-protocols/partenariat-automatique.md)).
4. **Perçage de NAT** (DCUtR) : deux pairs reliés par un relais tentent une
   connexion directe simultanée, en QUIC de préférence ; en cas de succès,
   le relais n'est plus utilisé.

## Annonce des adresses

L'entrée DHT Node ([`network.NodeEntry`](../02-schemas/network/NodeEntry.md))
porte, champ additif `addrs`, la liste des multiaddrs joignables : adresses
externes confirmées (TCP puis QUIC) d'abord, adresses via relais ensuite,
puis, ajout du 2026-11-22, ses adresses sur le réseau local (IPv4 privées).
Sans adresse externe ni relais, le Nœud publie donc quand même son entrée,
avec ses seules adresses locales : les Nœuds d'un même réseau local se
découvrent et deviennent partenaires sans être joignables depuis Internet.
Un pair qui partage un réseau local (même préfixe /24) avec le Nœud essaie
d'abord son adresse locale, sans dépendre du retour par la box.
`ip`/`port` restent l'adresse TCP directe (configurée par `public_ip`, sinon
détectée). Les pairs, la recherche de partenaires, la restauration et le
Connecteur essaient les adresses dans cet ordre.

## Connecteur

Le Connecteur n'accepte toujours aucune connexion entrante ; il sait joindre
un Nœud par QUIC, par relais et par perçage. Si son Nœud ne répond plus à
l'adresse configurée et qu'une DHT est configurée, il relit l'entrée Node et
essaie les adresses publiées.

## Limites

Deux Nœuds derrière des NAT symétriques, sans aucun Nœud public dans le
réseau, ne peuvent pas se joindre : il faut au moins un Nœud public (le
Nœud d'amorçage, par exemple).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
