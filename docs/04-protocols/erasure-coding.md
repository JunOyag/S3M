---
id: protocols.erasure-coding
kind: narrative
title: "Codage d'Effacement & Tolérance aux Pannes"
section: "§4.1"
status: draft
verified_by: []
---

# Codage d'Effacement & Tolérance aux Pannes (N = k + coef×k)

## Découpage & reconstruction

Les données sont découpées en k fragments. Le nœud calcule coef×k fragments
de parité (3k), soit N = k + coef×k par
[`dispersal.Stripe`](../02-schemas/dispersal/Stripe.md). La donnée initiale
est réassemblée dès lors que n'importe quels k fragments sur N sont
récupérés — y compris, en cas de perte totale du nœud hébergeur, à partir de
k fragments de parité seuls.

## Équité 1:1

Seuls les fragments **de parité** entrent dans le troc —
[`node.PartnerAccount`](../02-schemas/node/PartnerAccount.md#equilibre). Les k blocs
de données restent exclusivement locaux, jamais dans le troc.

## Paramètres fixes {: #parametres }

Ajout du 2026-11-21. **k = 4** et **coef = 3** (N = 16) sont des constantes
du logiciel : aucune configuration ne les modifie, et une valeur lue
ailleurs (`default_replication_coefficient` de
[`node.NodeConfig`](../02-schemas/node/NodeConfig.md), ancien fichier de
configuration) est ignorée.

## Dispersion multi-partenaires

Les coef×k blocs de parité d'une stripe sont dispersés vers **coef×k
partenaires distincts** — jamais deux fragments chez le même partenaire.
Avec coef=3, k=4 : 12 blocs de parité, donc **12 partenaires distincts**
minimum, chacun via la sélection par distance XOR
([`dispersal.Partner`](../02-schemas/dispersal/Partner.md)).

!!! note "Portée : archivage, pas de streaming"
    Le chaînage séquentiel `next_hash`
    ([`protocols.fs-structure`](fs-structure.md)) ne permet pas d'accès
    aléatoire (seek) sans parcourir toute la chaîne — le streaming vidéo ou
    la lecture aléatoire dans un fichier volumineux ne sont **pas** couverts
    par cette spécification.

## Assemblage progressif des stripes {: #assemblage-progressif }

Le Connecteur envoie les blocs **séquentiellement**. Le nœud les regroupe en
paquets de k.

- **Padding par timeout** : si moins de k blocs en attente pendant plus de
  `duree_max_idle_seconds`
  ([`node.NodeConfig`](../02-schemas/node/NodeConfig.md)), complétion par
  des blocs de padding (zéros, `is_padding=true`), puis calcul/dispersion de
  la parité de ce stripe partiel.
- **Remplacement a posteriori** : à réception des vrais blocs, le nœud
  remplace le padding et **recrée entièrement le stripe** — nouveau
  `stripe_id`, nouvelle parité, suivant le protocole transactionnel standard
  ([`protocols.dispersion-transactionnelle`](dispersion-transactionnelle.md)).
  L'ancien stripe est purgé via [`protocols.tombstones`](tombstones.md).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
