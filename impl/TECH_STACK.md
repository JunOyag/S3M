# impl/TECH_STACK.md — Choix des langages d'implémentation

Décision tranchée pour lever le point resté ouvert dans `AGENTS.md` §0.
Critères imposés : adéquation au développement par des agents IA,
stabilité, maintenabilité, rapidité (au sens performance).

## Décision

| Composant | Langage | Où |
|---|---|---|
| **Noyau partagé** (`impl/core`) | **Rust**, compilé nativement + en WASM (**sauf la VDF : natif uniquement**) | Primitives cryptographiques, Reed-Solomon (natif + WASM) ; VDF (natif, `chiavdf`) |
| **Nœud** (`impl/node`) | **Rust**, lie `impl/core` nativement | Démon hébergeur : réseau, stockage physique, PoS |
| **Connecteur** (`impl/connector`) | **TypeScript**, exécuté sur **Bun** | Client WebDAV, importe `impl/core` compilé en WASM ; charge `chiavdf` en natif pour la VDF |

Le Connecteur en TypeScript/Bun n'est pas un choix libre : c'est déjà ce
que dit la spec elle-même
([`deploiement.packaging`](../docs/07-deploiement/packaging.md) — *"généré
avec Bun"*). Le travail ici a été de choisir ce qui **n'était pas** déjà
tranché : le langage du Nœud, et comment éviter que deux langages
différents ne se traduisent par une logique cryptographique dupliquée (et
donc divergente) entre Nœud et Connecteur.

## Pourquoi un noyau partagé plutôt que deux implémentations

Ce projet documentaire a été construit tout du long sur un principe :
**aucun fait ne doit exister à deux endroits**. Étendre ce principe au code
serait incohérent si on laissait deux équipes réimplémenter chacune de leur
côté, en Rust et en TypeScript, les mêmes primitives cryptographiques
([`crypto.k-attach`](../docs/03-crypto/k-attach.md),
[`protocols.erasure-coding`](../docs/04-protocols/erasure-coding.md)) — le
risque n'est pas seulement la duplication d'effort, c'est la **divergence
silencieuse** de deux implémentations d'un même KDF ou d'un même code
correcteur, exactement la classe de bug la plus difficile à détecter en
revue de code.

**Solution retenue** : `impl/core` en Rust, compilé une fois nativement
(lié directement par le Nœud) et une fois en WebAssembly via
`wasm-pack`/`wasm-bindgen` (importé par le Connecteur, Bun ayant un support
WASM correct). Une seule implémentation, deux cibles de compilation.

**Exception : la VDF.** `chiavdf` est une bibliothèque C++/GMP pilotée par
CMake : elle ne produit pas d'artefact `wasm32-unknown-unknown`. La VDF est
donc la seule brique de `impl/core` **compilée en natif uniquement** (sous
`cfg(not(target_arch = "wasm32"))`) et le Connecteur la charge par une liaison
native, non par le pont WASM — voir « Exception : la VDF côté Connecteur »
ci-dessous.

**Ce qui va dans `impl/core`** (logique pure, sans I/O réseau/disque — donc
compilable en WASM sans douleur) :
- Toutes les clés de [`crypto.key-hierarchy`](../docs/03-crypto/key-hierarchy.md)
  (KDF, conversion Ed25519→X25519, wrapping `master_key_chain`).
- VDF de Wesolowski ([`network.vdf-identity`](../docs/01-network-dht/vdf-identity.md)) —
  génération **et** vérification, les deux étant nécessaires des deux
  côtés : un Connecteur vérifie l'identité d'un Nœud avant de s'y attacher,
  et **génère** lui-même sa propre identité User (§2.1 : la VDF s'applique
  aux identités Node et User). Seule exception à « compilable en WASM » :
  cette brique est **native uniquement** (voir ci-dessous).
- Reed-Solomon encode/decode ([`protocols.erasure-coding`](../docs/04-protocols/erasure-coding.md)) —
  le Nœud encode, le Connecteur décode en chemin de secours ; c'est la
  même bibliothèque, pas deux.
- Agilité post-quantique ([`agilite.*`](../docs/08-agilite-crypto/kem-vs-nike.md)).

**Ce qui n'y va PAS** : les types générés par `flatc` depuis `schemas/**/*.fbs`
sont émis **nativement par langage** (Rust pour `impl/core`/`impl/node`, TS
pour `impl/connector`) — `flatc` sait déjà le faire pour les deux cibles,
et ce sont de simples layouts de données zero-copy, pas de la logique :
les partager via WASM n'apporterait rien et ajouterait une couche
d'indirection inutile.

**Ce qui reste délibérément non partagé** : la pile réseau
([`network.dht-directory`](../docs/01-network-dht/dht-directory.md)) —
`rust-libp2p` côté Nœud, `js-libp2p` côté Connecteur. Le WASM n'est pas
adapté aux sockets réseau bas niveau ; l'interopérabilité se fait au niveau
du protocole libp2p lui-même (les deux implémentations parlent le même
protocole de fil), pas au niveau du code.

## Pourquoi Rust pour le Nœud et `impl/core`

Face aux quatre critères :

- **Adéquation à l'IA** : le compilateur Rust (emprunt, durées de vie,
  exhaustivité du pattern matching) constitue une boucle de rétroaction
  extrêmement serrée pour un agent — une classe entière de bugs (data
  races, use-after-free, désérialisation FlatBuffers mal bornée) est
  rejetée *avant même l'exécution*, plutôt que découverte en production.
  C'est un vrai compromis : le code d'un agent met plus d'itérations à
  compiler qu'en Go ou TypeScript, mais une fois qu'il compile, une
  catégorie de bugs silencieux est déjà éliminée — précieux quand
  plusieurs agents travaillent en parallèle sans revue humaine systématique
  (voir `AGENTS.md` §3, définition du "terminé").
- **Stabilité** : garanties de compatibilité par édition, écosystème mature
  sur exactement les briques dont ce projet a besoin (voir bibliothèques
  ci-dessous), utilisé en production sur des systèmes de stockage distribué
  comparables (IPFS, Substrate/Polkadot s'appuient sur `rust-libp2p`).
- **Maintenabilité** : `cargo clippy` + `rustfmt` imposent un style uniforme
  sans effort humain — utile pour une équipe d'agents multiples dont le
  code doit rester cohérent sans repasser par une seule main.
- **Rapidité** : pas de ramasse-miettes (latence prévisible, important pour
  un démon long-running qui sert aussi des challenges PoS avec un
  [timeout strict](../docs/05-securite/pos-challenges.md)), compilation
  native, empreinte mémoire faible — cohérent avec le déploiement visé
  ([`deploiement.packaging`](../docs/07-deploiement/packaging.md) : NAS,
  Raspberry Pi).

### Alternative envisagée et écartée : Go pour le Nœud

Go aurait été un candidat sérieux — `go-libp2p` est l'implémentation
libp2p historique de référence (IPFS), la courbe d'apprentissage est plus
douce, et les agents produisent généralement du Go correct plus vite qu'du
Rust dès le premier essai. Écarté principalement pour une raison : le VDF
de Wesolowski (§2.1) réclame de l'arithmétique de groupe de classes
(formes quadratiques, algorithme NUDUPL) — un terrain **extrêmement
casse-gueule** pour du code écrit par un agent sans audit humain
approfondi, où l'écosystème Go n'offre essentiellement rien de mûr,
obligeant à des bindings CGo vers une bibliothèque C++ de toute façon
(voir ci-dessous) — perdant l'avantage "tout Go" recherché. Rust, lui,
a un écosystème de liaison FFI plus discipliné pour ce cas précis.

## Connecteur : TypeScript sur Bun — réexamen (bien fondé, pas juste hérité de la spec)

Le premier jet de cette décision s'appuyait uniquement sur l'indice de la
spec (§7.3, "généré avec Bun") sans vérifier l'état réel de l'écosystème.
Trois points méritaient d'être vérifiés avant de la confirmer :

**1. Bun a été racheté par Anthropic en décembre 2025** — Bun est
désormais l'infrastructure sur laquelle tourne Claude Code lui-même
(distribué comme exécutable Bun unique à des millions de développeurs).
Anthropic a donc un intérêt financier direct à garder Bun excellent : si
Bun casse, Claude Code casse avec. Ça déplace fortement le critère
« stabilité » dans le bon sens — un projet self-hébergé de stockage P2P
n'a normalement aucune garantie de continuité d'un outil tiers à un tel
horizon, ici si.

Nuance à ne pas passer sous silence : plusieurs contributeurs historiques
de l'équipe Oven (pré-rachat) ont quitté le projet dans les mois qui ont
suivi — un phénomène de turnaround normal en cas de M&A, mais réel. Le
projet reste activement maintenu par Anthropic, sous licence MIT, en
public sur GitHub.

**2. Bun réécrit actuellement ses propres internals de Zig vers Rust**
(effort lancé en mai 2026, plus d'un million de lignes), explicitement pour
« empêcher systématiquement la récurrence de bugs mémoire ». C'est une
validation indépendante et amusante du choix de Rust fait plus haut pour
`impl/core`/`impl/node` — même l'équipe qui construit le runtime cible
fait le même pari sur Rust, pour les mêmes raisons de sûreté mémoire.

**3. Le pont vers `impl/core` : WASM confirmé plus adapté que le FFI natif
(`bun:ffi`)** — contrairement à mon hypothèse initiale non vérifiée qu'un
appel FFI natif serait plus rapide qu'un pont WASM, des benchmarks
Rust-vers-Node comparant explicitement les deux approches sur la même
tâche montrent le **WASM significativement plus rapide que le FFI natif**
(la liaison dynamique et le marshalling de données coûtent plus cher en
FFI qu'en WASM, qui bénéficie d'une intégration au niveau du compilateur).
Le WASM apporte en prime une propriété de sécurité que le FFI natif
n'offre pas : un bug dans `impl/core` reste cantonné dans le bac à sable
WASM plutôt que de pouvoir corrompre la mémoire du process hôte — pertinent
puisque ce noyau traite des données reçues de partenaires potentiellement
malveillants (blocs de parité, réponses PoS). Bun a un support WASM natif
documenté et fonctionnel pour ce cas d'usage (charger un module `.wasm`
compilé par `wasm-pack`/`wasm-bindgen`) ; la seule réserve connue porte sur
le support WASI (accès système depuis le WASM lui-même), qui ne nous
concerne pas puisque `impl/core` est de la logique pure (aucun accès
disque/réseau depuis le WASM — c'est Bun, côté hôte, qui fait tout l'I/O et
ne passe que des buffers en entrée/sortie).

**Conclusion du réexamen : la décision initiale (TypeScript/Bun + pont
WASM vers `impl/core`) est confirmée, avec un niveau de confiance plus
élevé qu'au premier jet — à une exception près, la VDF (voir la
sous-section suivante), qui ne peut pas passer par le pont WASM.** Bonnes pratiques à appliquer dès la mise en
place du pont :
- Profil de compilation du crate WASM : `opt-level = "s"` + `lto = true`
  (garde le `.wasm` compact, le chargement asynchrone d'un gros module
  WASM étant le principal point de friction documenté sur Bun).
- Isoler les appels spécifiques à Bun (`Bun.serve`, `bun:sqlite`, etc.)
  derrière de fines interfaces dans `impl/connector`, plutôt que de les
  disperser dans tout le code — assurance peu coûteuse pour absorber une
  éventuelle instabilité passagère de l'écosystème post-rachat en migrant
  vers Node.js/Deno si jamais nécessaire, sans réécriture complète.

### Exception : la VDF côté Connecteur

Le Connecteur a besoin de la VDF **en génération et en vérification** :
génération de sa propre identité User, vérification de l'identité des Nœuds
et des entrées DHT. Comme `chiavdf` ne se compile pas en WASM, le Connecteur
passe par une **liaison native**, par plateforme. La forme exacte reste à
arbitrer en passe code :

- **`bun:ffi`** : bibliothèque dynamique chargée dans le process Bun ;
  simple, mais un bug du code natif peut corrompre la mémoire du process
  hôte (le bac à sable que le WASM aurait offert disparaît).
- **Binaire sidecar** : `chiavdf` dans un processus séparé, appelé depuis
  Bun ; l'isolation est conservée, au prix d'un artefact de plus à
  distribuer.

Les appels VDF étant rares (une génération par identité, quelques
vérifications par résolution) et dominés par le calcul, le surcoût de
marshalling ne départage pas les deux options. Dans les deux cas :

- l'interface avec `chiavdf` reste derrière une fine interface dans
  `impl/connector` (même principe que pour les appels spécifiques à Bun,
  ci-dessus), pour pouvoir changer de mécanisme sans réécriture ;
- les entrées étant fournies par des pairs potentiellement hostiles, le
  contrôle des longueurs est obligatoire avant tout appel (voir « Contraintes
  du binding `chiavdf` ») ;
- le Connecteur n'est plus un exécutable entièrement autonome : il
  embarque une bibliothèque native par plateforme, ce qui nuance la
  formulation « exécutable portable » de
  [`deploiement.packaging`](../docs/07-deploiement/packaging.md) — à refléter
  dans cette page.

## Bibliothèques spécifiques à ne PAS réimplémenter

Deux endroits de la spec sont mathématiquement assez subtils pour que la
bonne décision d'ingénierie soit de **lier une bibliothèque auditée**
plutôt que de laisser un agent écrire l'arithmétique depuis zéro :

- **VDF de Wesolowski sur groupe de classes** — le réseau Chia résout
  exactement ce problème en production (c'est la même construction :
  discriminant négatif, `Cl(Δ)`, preuve de Wesolowski). Lier
  `impl/core` à la crate `chiavdf` 1.1.14 (bibliothèque C++ du réseau Chia,
  interface C exposée, bindings Rust générés par `bindgen`), plutôt que de
  demander à un agent d'implémenter NUDUPL lui-même. Un bug ici casserait
  la propriété anti-Sybil de tout le réseau — risque disproportionné par
  rapport au gain d'avoir "tout en Rust pur". Les paramètres de protocole
  (taille du discriminant, nombre d'itérations, dérivation de `Δ`) sont
  définis dans [`network.vdf-identity`](../docs/01-network-dht/vdf-identity.md)
  et ne sont pas répétés ici.
- **Reed-Solomon** — la crate `reed-solomon-erasure` (Rust, implémentation
  GF(2⁸) largement utilisée en production) plutôt qu'un réimplémentation.

Le reste (suite symétrique AEAD/KDF/hash, conversions Ed25519/X25519,
wrapping de clés) est suffisamment simple et bien couvert par des
bibliothèques standard (`chacha20poly1305`, `hkdf`, `hmac`, `sha2`,
`ed25519-dalek`, `x25519-dalek`) pour qu'un agent les compose correctement,
sous réserve de tests couvrant les vecteurs de test connus des standards
concernés (RFC 7748, RFC 8032, RFC 8439, RFC 5869, RFC 4231, RFC 6234).

## Bibliothèques retenues, par composant

| Besoin | `impl/core` (Rust) | `impl/connector` (TS/Bun) |
|---|---|---|
| Ed25519 / X25519 | `ed25519-dalek`, `x25519-dalek` | *(via WASM depuis `impl/core`)* |
| Suite symétrique — AEAD ChaCha20-Poly1305, HKDF-SHA256, SHA-256, HMAC-SHA256 ([`crypto.symmetric-suite`](../docs/03-crypto/symmetric-suite.md)) | `chacha20poly1305`, `hkdf`, `sha2`, `hmac` | *(via WASM depuis `impl/core`)* |
| VDF Wesolowski | crate `chiavdf` 1.1.14 (**natif uniquement**, `cfg(not(target_arch = "wasm32"))`) | liaison **native** : `bun:ffi` ou binaire sidecar — génération **et** vérification, **pas de WASM** |
| Reed-Solomon | `reed-solomon-erasure` | *(via WASM)* |
| Sérialisation réseau | `flatbuffers` (crate officielle) | `flatbuffers` (paquet npm officiel) |
| libp2p | `rust-libp2p` | `js-libp2p` |
| Stockage local (Nœud) | `rusqlite` (WAL) ou `heed` (LMDB) | — |
| Fichiers creux / hole-punching | `nix` (`fallocate` via `libc`/`rustix`) | — |
| WebDAV | — | `webdav-server` ou implémentation légère sur `Bun.serve` |

## Contraintes du binding `chiavdf`

Constatées à la lecture de la crate (`lib.rs`) et validées par les tests de
la CI :

- L'interface publique se réduit à trois fonctions : `create_discriminant`,
  `prove` et `verify_n_wesolowski`. La bibliothèque ne fournit ni hash
  vers forme, ni arithmétique de formes : ne pas en écrire à côté.
- La taille du discriminant est plafonnée par la bibliothèque (voir la
  valeur retenue dans `network.vdf-identity`) ; la dépasser fait échouer
  la génération et la vérification.
- Les entrées sont à taille fixe (forme de départ, preuve, discriminant).
  `verify_n_wesolowski` transmet la forme de départ à la couche C++
  **sans sa longueur** : le wrapper Rust doit donc vérifier les trois
  longueurs avant tout appel, sous peine de lecture hors limites sur une
  entrée venant d'un pair hostile.
- Le vérificateur recalcule `Δ` à partir de `pub_key` ; il n'accepte
  jamais un `Δ` fourni par le prouveur.
- Tests à couvrir, avec borne de temps : aller-retour valide, octet
  altéré, mauvais `T`, preuve rejouée pour une autre identité (déjà
  validés en CI), puis preuve vide ou tronquée, octets aléatoires,
  `T = 0`, `T = u64::MAX`, `recursion ≠ 0` (à ajouter).

## Environnement de build et CI (`chiavdf`)

La crate compile du C++ par CMake et génère ses bindings avec `bindgen`
(libclang). Plateformes validées en CI (GitHub Actions : `windows-latest`,
`ubuntu-latest`, `ubuntu-24.04-arm`, `macos-latest`) :

| Plateforme | Dépendances de build |
|---|---|
| Linux (x86, ARM) | `cmake`, `libgmp-dev`, `libclang-dev` |
| macOS | `brew install gmp cmake`, avec `CPATH` et `LIBRARY_PATH` pointant vers le préfixe de `gmp` |
| Windows | Visual Studio (MSVC) + `cmake` + LLVM ; `LIBCLANG_PATH` vers le `bin` de LLVM ; **ne pas écraser `INCLUDE`** (bindgen ne retrouverait plus les en-têtes système) |

- **Windows : MSVC uniquement.** La crate embarque sa propre MPIR pour
  MSVC. La chaîne MinGW n'est pas supportée : le build exige un `mpir`
  MSVC, et avec une bibliothèque de substitution le prouveur est resté
  bloqué à l'exécution lors de l'essai. Elle est exclue.
- **Les builds et tests de la VDF tournent en CI.** Une machine de
  développement Windows sans droits d'administration ne peut pas installer
  l'outillage MSVC et ne compile donc pas `chiavdf` en local ; les autres
  briques de `impl/core` restent compilables et testables localement.
- **Exécution sous Windows** : les DLL de MPIR (`mpir.dll` et ses variantes
  par processeur) doivent se trouver à côté du binaire, et le runtime Visual
  C++ (`MSVCP140`, `VCRUNTIME140`, `VCRUNTIME140_1`) être présent sur la
  machine. **La licence de MPIR est à faire valider avant toute
  distribution.**
- La feature `wasm` de `impl/core` exclut la VDF par
  `cfg(not(target_arch = "wasm32"))`, pour que `wasm-pack` ne tente jamais
  de compiler `chiavdf`.

## Ce que ça change dans `AGENTS.md`

Le point laissé ouvert en `AGENTS.md` §0 est résolu : voir la mise à jour
de ce fichier et de `impl/layers.yml`, qui porte désormais un champ
`component` (`core` / `node` / `connector` / `node+connector`) par id,
pour qu'un agent orchestrateur sache directement dans quel sous-répertoire
assigner chaque tâche.
