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
trace de fin; à ce stade, aucun cross-check n'avait abouti. Le binaire natif
observé n'importe pas de DLL MPIR/GMP; le `build.rs` de chiavdf déclare MPIR
statique sous Windows. Ces observations ne prouvent pas à elles seules
quelle archive statique a été retenue.

#### Cross-check MPIR CI communiqué (19/10/2026)

Le workflow `.github/workflows/vdf-verifier-pure.yml` a ensuite réussi le
test ciblé
`cargo test --features vdf --lib vdf_pure::tests::mpir_cross_check -- --nocapture --test-threads=1` :
**3 tests réussis, 0 échec**. MPIR et le vérificateur pur ont accepté les
vecteurs legacy et tagged générés avec `T=100`; le test tagged vérifie aussi
le rejet d'un tag `key_algorithm` différent et le rejet pur d'un encodage
non canonique que le décodeur MPIR accepte. Les mesures rapportées par ce
run sont :

| Opération | Durées rapportées |
|---|---|
| `chiavdf::prove` | **22,1663 ms**, **35,3954 ms**, **15,1582 ms** |
| vérification MPIR | **4,6212 ms**, **4,9302 ms**, **4,9001 ms**, **6,4109 ms**, **5,5881 ms** |
| vérification pure | **789,9214 ms**, **1,0670431 s**, **880,6922 ms**, **441,9288 ms** |
| `create_discriminant` | **9,2829–44,0067 ms** |

Ce sont les mesures fournies pour ce run; elles ne sont pas extrapolées.
Les trois tests réussis ne couvraient pas les rejets après altération de `y`
et de la clé publique. Le test WASM précédent s'exécute sur le vecteur Chia
exact de 200 octets, mais mesure un rejet parce que `[0x42; 32]` est passé
comme clé legacy et haché avant dérivation du challenge; ce n'est ni le
vecteur généré par MPIR, ni une acceptation positive.

La fixture taguée MPIR T=100 est maintenant versionnée dans
`impl/core/tests/fixtures/vdf_tagged_identity_t100.hex` (identité
`0x07 || [0x31; 32]`). Le test natif compare la sortie de `chiavdf::prove`
à cette fixture, puis fait vérifier par MPIR et Rust la preuve intacte, la
preuve avec un octet de `y` altéré, et la preuve avec un octet de clé publique
modifié. Le rejet pur d'un encodage non canonique que MPIR accepte reste
testé séparément.

Un test interne `wasm-bindgen-test` vérifie la même fixture en WASM à T=100,
accepte la preuve intacte et rejette les mutations de `y` et de la clé
publique. Il utilise la fonction privée à itérations explicites pour ne pas
exposer de nouvelle API de production; le job Node/WASM correspondant est
ajouté à `.github/workflows/vdf-verifier-pure.yml`. Les trois tests MPIR
natives passent localement contre la DLL MPIR embarquée; le test WASM passe
également sous Node. Le run GitHub Actions demandé reste à faire; jusqu'à
réception de ses résultats, le statut reste `in_progress` et `verified_by`
reste vide. Aucun paramètre ou algorithme distinct de ceux de
[`network.vdf-identity`](vdf-identity.md) n'est introduit.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
