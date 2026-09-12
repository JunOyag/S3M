---
id: protocols.migration-noeud
kind: narrative
title: "Migration vers un Nouveau Nœud"
section: "§3.7.1"
status: draft
verified_by: []
---

# Migration vers un Nouveau Nœud (Déménagement)

À tout moment, l'utilisateur peut changer de nœud hébergeur — que l'ancien
Nœud soit encore accessible ou définitivement perdu (ce cas couvre donc
aussi la reprise après perte totale du Nœud).

## Déroulé

1. Le Connecteur attache l'Utilisateur au nouveau Nœud (nouveau `salt`),
   permettant à chaque partie de dériver un nouveau
   [`crypto.k-attach`](../03-crypto/k-attach.md).
2. **Le Connecteur seul** — jamais le nouveau Nœud — re-dérive l'**ancien**
   `K_attach` et l'utilise **uniquement** pour déchiffrer l'entrée DHT
   elle-même, obtenant `dispersal_root_hash`/`dispersal_root_partners`, puis
   calcule `K_dispersal_content`
   ([`crypto.k-dispersal`](../03-crypto/k-dispersal.md)). Il transmet au
   nouveau Nœud **ces trois éléments** — jamais l'ancien `K_attach` ni
   `sig_priv_dispersal`. **Aucune coopération de l'ancien Nœud n'est
   requise**, et le nouveau Nœud n'a structurellement jamais les moyens de
   signer quoi que ce soit sur l'ancienne entrée DHT.
3. Pour chaque stripe, le nouveau Nœud récupère k fragments de parité
   auprès de ces partenaires et reconstruit les k blocs de données
   originaux ([`protocols.erasure-coding`](erasure-coding.md)).
4. Il recalcule et disperse une nouvelle parité vers **ses propres
   partenaires** (pouvant recouper, en tout ou partie, les précédents)
   selon le protocole transactionnel standard
   ([`protocols.dispersion-transactionnelle`](dispersion-transactionnelle.md)).
5. Il publie une nouvelle entrée DHT `DispersalManifest`, sous sa propre
   `sig_pub_dispersal`. L'ancienne entrée devient **orpheline** et suit le
   régime d'expiration standard : sans republication, elle expire au plus
   tard après 6 mois.

## Limite résiduelle

L'entrée DHT `DispersalManifest` porte une durée de vie de 6 mois — si le
Nœud d'origine est réellement hors service, elle expire dans la même
fenêtre que son entrée `Node`. Le risque résiduel porte sur l'érosion des
blocs de parité chez les partenaires pendant cette fenêtre : si trop de
partenaires ont été purgés sans réparation avant l'expiration, le nombre de
fragments récupérables peut passer sous le seuil k.

## Variante : perte sans compromission

Voir [`securite.incidents-compromissions`](../05-securite/incidents-compromissions.md#variante-perte-sans-compromission)
pour le cas où l'opérateur a perdu l'accès matériel sans compromission
avérée — les partenaires d'origine sont alors conservés plutôt que
renouvelés.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
