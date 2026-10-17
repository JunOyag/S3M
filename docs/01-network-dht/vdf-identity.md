---
id: network.vdf-identity
kind: narrative
title: "VDF de Wesolowski — Identités anti-Sybil"
section: "§2.1"
status: draft
verified_by: []
---

# VDF de Wesolowski — Identités anti-Sybil

Contrairement à une Proof of Work classique (parallélisable — un attaquant
disposant de N machines peut produire N identités dans le même temps
physique qu'une seule machine), la génération d'une nouvelle identité (Node
ou User) repose sur une **Fonction à Délai Vérifiable (VDF)**, dont la
séquentialité est prouvée : aucune quantité de matériel parallèle ne permet
d'en réduire le temps de calcul.

## Paramètres de protocole

Ces constantes sont partagées par tous les générateurs et vérificateurs ;
en changer une invalide les identités déjà produites et passe donc par une
nouvelle version de la spécification.

| Paramètre | Valeur | Remarque |
|---|---|---|
| `DISCRIMINANT_BITS` (λ) | **1024** | Plafond de la bibliothèque `chiavdf` 1.1.14 ; paramètre utilisé par Chia en production |
| `T` (itérations) | **5 400 000** | Durées mesurées : voir [Calibration de `T`](#calibration-de-t) |
| `recursion` | **0** | Preuve de Wesolowski simple, sans récursion |
| Hash du challenge et de la dérivation de `Δ` | SHA-256 | |
| Taille de la preuve `y ‖ π` | 200 octets | 100 octets pour `y`, 100 pour `π` |
| Taille du discriminant sérialisé | 128 octets | `λ / 8` |
| Taille de la forme de départ | 100 octets | Sérialisation BQFC, voir [Calcul séquentiel](#calcul-sequentiel-et-preuve) |

## Setup — un discriminant `Δ` par identité

Le groupe utilisé est la classe de formes quadratiques imaginaires `Cl(Δ)`
pour un discriminant `Δ` **négatif, dérivé du challenge de l'identité** :
`Δ` n'est donc pas un paramètre global, mais il n'est pas non plus choisi
par le prouveur — il découle d'un hash public de `pub_key`. Contrairement à
un groupe RSA (module `N = p·q` nécessitant une cérémonie MPC pour garantir
que sa factorisation reste inconnue), l'ordre de `Cl(Δ)` est
structurellement inconnu de quiconque dès lors que `Δ` est dérivé de façon
vérifiable et non malléable — **pas de cérémonie de confiance requise**.

La dérivation, identique pour le prouveur et le vérificateur :

1. `challenge = SHA-256(pub_key)`, où `pub_key` inclut son tag
   `key_algorithm` (voir l'agilité cryptographique, §8.4 de la
   spécification).
2. `p = HashPrime(challenge, 1024)` : on parcourt la chaîne de hashes
   SHA-256 du seed `challenge` incrémenté, et `p` est le **premier candidat
   qui passe le test de primalité**, après application d'un masque de bits
   `{0, 1, 2, λ−1}` (bits de poids faible 0, 1 et 2 forcés à 1 ; bit de poids
   fort `λ−1` forcé à 1). Il en découle `p ≡ 7 mod 8`, donc `p ≡ 3 mod 4`,
   et `p ≥ 2^(λ−1)`.
3. `Δ = −p`.

Cette procédure est celle implémentée par `create_discriminant` de
`chiavdf` ; son résultat est validé contre le vecteur de référence Python de
la bibliothèque. N'importe qui peut la rejouer à partir de `pub_key` et
vérifier qu'aucun choix arbitraire n'a permis d'introduire une trappe. Son
coût est de l'ordre de 10 ms pour 1024 bits.

**Le vérificateur recalcule toujours `Δ` lui-même à partir de `pub_key`** et
n'accepte jamais un `Δ` fourni par le prouveur : sinon, une preuve calculée
une seule fois pour un discriminant choisi serait réutilisable pour toutes
les identités.

## Calcul séquentiel et preuve

- La forme de départ `x_s` est fixe : c'est l'élément par défaut de
  `chiavdf`, sérialisé au format BQFC sur 100 octets (premier octet `0x08`,
  99 octets à zéro). C'est le **discriminant**, et non la forme de départ,
  qui porte l'identité : deux identités distinctes calculent donc dans des
  groupes `Cl(Δ)` différents, et une preuve n'est pas réutilisable d'une
  identité à l'autre.
  > **À confirmer** dans `bqfc.h` : désignation exacte de cet élément (forme
  > génératrice ou autre élément de référence) avant le gel de la page.
- `y = g^(2^T)`, où `g` est la forme de départ, est calculé par `T` mises au
  carré successives dans `Cl(Δ)` (algorithme NUDUPL) — chaque étape dépendant
  strictement de la précédente.
- **Preuve de Wesolowski** : une preuve courte `π = g^⌊2^T/ℓ⌋`, où `ℓ` est un
  nombre premier dérivé de façon déterministe par `chiavdf` (ce n'est pas un
  paramètre de protocole), permet à tout pair DHT de vérifier
  `y = π^ℓ · g^r` en temps logarithmique, sans rejouer les `T` mises au
  carré. Coût de génération élevé et incompressible ; coût de vérification
  négligeable (de l'ordre de 20 ms mesurés, recalcul de `Δ` compris).
- La génération `prove(challenge, x_s, 1024, T)` renvoie `y ‖ π`, soit
  **200 octets**. Le tuple joint à toute nouvelle entrée DHT Node ou User est
  `(pub_key, y ‖ π)` : `T`, `recursion`, `λ` et la dérivation de `Δ` sont
  fixés une fois par la spécification, implicites pour tout vérificateur.

### Entrées non fiables

La preuve et la clé publique proviennent de pairs potentiellement hostiles.
Avant tout appel à `chiavdf`, l'implémentation impose les longueurs
suivantes : forme de départ de 100 octets, preuve de 200 octets,
discriminant de 128 octets. La bibliothèque ne reçoit pas la longueur de la
forme de départ lors de la vérification : ce contrôle appartient à
l'appelant.

## Calibration de `T`

`T = 5 400 000` est la valeur de protocole. Les durées de génération qui en
découlent varient fortement avec la plateforme. Mesures (médiane de
5 preuves, `T = 1 000 000`, `chiavdf` 1.1.14, runners cloud partagés) :

| Plateforme | CPU | Débit (it/s) | Durée de `T = 5 400 000` |
|---|---|---|---|
| Linux ARM | Neoverse-N2 | 175 606 | 31 s |
| Linux x86 | Intel Xeon Platinum 8573C | 131 254 | 41 s |
| macOS | Apple M1 (virtuel) | 124 828 | 43 s |
| Windows | AMD EPYC 7763 | 65 068 | 83 s |

L'ordre de grandeur est donc de **30 s à 1,5 min selon la plateforme**. Aucune
machine unique n'est désignée comme référence. Limites de ces mesures :

- une seule série de mesures par plateforme, sur des machines virtuelles
  partagées : ce sont des ordres de grandeur, non une référence
  reproductible ;
- l'écart d'environ 2× de Windows n'est pas expliqué (processeur,
  compilateur et bibliothèque MPIR/GMP varient simultanément) ;
- le Raspberry Pi, cible du Nœud, n'a pas été mesuré.

La valeur de `T` sera réexaminée si une mesure sur Raspberry Pi, une
explication de l'écart Windows ou des mesures ultérieures le justifient.

## Limite connue

Ce coût dissuade la génération massive et parallèle d'identités, mais
n'empêche pas, en théorie, une régénération après le délai minimal. Ce délai
dépend du matériel de l'attaquant : le coût réel d'une fausse identité est
celui de la machine la plus rapide dont il dispose (de 31 s à 83 s pour
`T = 5 400 000` sur les plateformes mesurées), alors qu'un utilisateur
honnête subit le temps de sa propre machine. Pertinent notamment pour le
contournement de la liste noire — voir
[`securite.blacklist-fraude`](../05-securite/blacklist-fraude.md#note-de-conception).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
