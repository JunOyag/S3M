---
id: network.vdf-verifier-pure
kind: narrative
title: "Vérificateur VDF pur — conformité native et WASM"
section: "§2.1"
status: draft
verified_by: []
---

# Vérificateur VDF pur — conformité native et WASM

Cette page définit le contrat de conformité du vérificateur VDF partagé dans
`impl/core` pour les cibles natives et WASM. Elle complète
[`network.vdf-identity`](vdf-identity.md) : elle ne définit ni une nouvelle
construction VDF ni un algorithme alternatif à la preuve de Wesolowski qui y
est spécifiée.

## Contrat de vérification

- Le vérificateur applique les paramètres, la dérivation du discriminant et
  les règles de validation des entrées définis dans
  [`network.vdf-identity`](vdf-identity.md). En particulier, il recalcule le
  discriminant à partir de la clé publique et vérifie la preuve de
  Wesolowski ; le discriminant fourni par un appelant n'est pas une entrée de
  confiance.
- La vérification est du Rust pur, disponible pour les cibles natives et
  WASM. Son chemin de production ne dépend pas de MPIR. Il applique le même
  contrat protocolaire sur les deux cibles et ne remplace pas les règles
  communes de rejet des entrées malformées.
- Pour une identité taguée, l'entrée est exactement
  `key_algorithm` (un octet) `|| raw_public_key`. Le vérificateur calcule
  `SHA-256` sur tous les octets de cette séquence, tag compris, puis dérive
  le discriminant de ce challenge. La clé brute n'est pas hachée seule et
  aucun discriminant fourni par l'appelant n'est digne de confiance. Cette
  dépendance d'implémentation à `network.vdf-identity-tagged` est indiquée
  dans `impl/layers.yml`; le lien documentaire correspondant sera ajouté
  lorsque l'id tagged sera intégré au manifeste. L'API legacy à clé brute
  de 32 octets reste disponible pour compatibilité avec
  [`network.vdf-identity`](vdf-identity.md).

## Conformité et tests

Les tests natifs vérifient l'acceptation d'un vecteur Chia de référence et le
rejet d'une preuve altérée, d'un challenge incorrect, d'itérations incorrectes
et de formes malformées. Les tests MPIR dédiés régénèrent une preuve avec
`T=100` uniquement pour le test, puis comparent les décisions des deux
implémentations; les API de production restent fixées au `T` protocolaire.
MPIR sert à produire ou comparer les vecteurs de test uniquement : il ne doit
pas être requis par le vérificateur utilisé en production.

### Mesures et vérifications locales (19/10/2026)

Le test WASM dédié est `impl/core/tests/vdf_pure_wasm.rs` et s'exécute avec
`wasm-bindgen-test-runner` sous Node. La commande
`CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner cargo test
--target wasm32-unknown-unknown --features wasm --test vdf_pure_wasm --
--nocapture` a réussi : 1 test. Avec le vecteur corrigé, l'appel au vérificateur
a duré **9,3989309 s**, **6,0384659 s** puis **11,0517409 s** lors d'une
troisième exécution fraîche; la variabilité observée est donc visible. Le
harnais contient exactement la constante native `PROOF_HEX` (400 caractères,
200 octets) et décode directement cette constante, sans concaténation ni
padding. Le vecteur Chia utilise
`[0x42; 32]` directement comme challenge; le harnais appelle l'API legacy avec
ces mêmes octets comme clé, dont le challenge est dérivé par SHA-256. Le rejet
attendu n'est donc pas une acceptation positive WASM du vecteur. L'ancienne
mesure WASM antérieure à cette correction utilisait 173 octets complétés de
zéros; elle ne représente pas le même vecteur et est exclue des résultats.
Ce vecteur Chia embarqué n'est pas une fixture produite par MPIR.

#### Diagnostic MPIR borné, `T=100`

Les traces sont horodatées (millisecondes Unix) avant et après les appels
accessibles. Une exécution ciblée de `legacy_identity_mpir_vector_matches`
avec `--nocapture --test-threads=1` et une limite d'observation de 30 secondes
a produit :

| Étape | Mesure |
|---|---|
| `chiavdf::create_discriminant` explicite, 19/10 à `13:58:22.034Z` | fin à `13:58:22.044Z`, **10,1966 ms** |
| hash-to-form / `DeserializeForm` | non exposé par opération séparée dans l'API Rust; le wrapper `prove` le fait en interne |
| `chiavdf::prove` | début à `13:58:22.044Z`; toujours actif après **au moins 30 s**, puis arrêt de ce test ciblé. Pas de trace de fin ni durée totale |
| `chiavdf::verify_n_wesolowski` après génération | non atteint |

Un essai antérieur du même `prove(T=100)` avait démarré à
`13:12:09.700Z` et était resté actif plus de 200 s avant arrêt manuel. À cet
essai, l'appel explicite préalable à `create_discriminant` avait duré
**5,9234 ms** (début `13:12:09.693Z`, fin `13:12:09.699Z`).

Selon les sources chiavdf 1.1.14 (`src/lib.rs`,
`cpp/c_bindings/c_wrapper.cpp`, `cpp/prover_slow.h`), le wrapper `prove`
recalcule le discriminant, désérialise la forme initiale puis appelle
`ProveSlow`. Dans `ProveSlow`, une boucle séquentielle `nudupl_form`/réduction
évalue les itérations avant l'appel à `GenerateWesolowski`, qui calcule la
preuve; les formes sont ensuite sérialisées. L'API publique `chiavdf::prove`
ne donne pas accès aux frontières de ces deux blocs internes. La durée
observée (ou sa borne minimale) concerne donc l'appel combiné complet et ne
peut être attribuée à l'évaluation séquentielle seule.

La vérification MPIR indépendante du vecteur Chia existant (non généré par
MPIR) avait précédemment mesuré `create_discriminant` à **12,7113 ms**
(`13:40:13.162Z`–`13:40:13.174Z`). `verify_n_wesolowski` avait démarré à
`13:40:13.175Z`, dépassé 180 s et été arrêtée manuellement sans résultat ni
trace de fin. Aucun cross-check n'a abouti et aucune fixture MPIR n'a été
générée. Le binaire natif observé n'importe pas de DLL MPIR/GMP; le `build.rs`
de chiavdf déclare MPIR statique sous Windows. Ces observations ne prouvent
pas à elles seules quelle archive statique a été retenue.

`cargo test`, Clippy avec et sans `--features vdf`, `mkdocs build --strict`,
`python scripts/status.py`, `python scripts/plan.py --graph schema`,
`git diff --check` et `rustfmt --check` ciblé ont réussi. Les fixtures MPIR
versionnées et l'accord sur la comparaison MPIR au `T` protocolaire restent
absents; le statut demeure `in_progress` et `verified_by` reste vide. Aucun
paramètre ou algorithme distinct de ceux de
[`network.vdf-identity`](vdf-identity.md) n'est introduit.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
