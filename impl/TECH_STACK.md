# impl/TECH_STACK.md — Choix des langages d'implémentation

Décision de stack du chantier. Critères imposés : adéquation au
développement par des agents IA, stabilité, maintenabilité, rapidité (au
sens performance).

> **Révision V3 (2026-11-19)** : le Connecteur passe de TypeScript/Bun à un
> **binaire Rust natif** (`ST-S3M-2026-V3-modifications.md` §1,
> §11). Conséquences : plus aucune cible WASM, un crate `impl/protocol`
> partagé par le Nœud et le Connecteur, et le vérificateur VDF maison est
> retiré (`chiavdf` est le seul vérificateur). L'ancienne justification
> TypeScript/Bun + pont WASM reste lisible dans l'historique git de ce
> fichier.

## Décision

| Composant | Langage | Rôle |
|---|---|---|
| **Noyau** (`impl/core`) | **Rust**, natif uniquement | Primitives pures, sans I/O : suite symétrique, dérivations de clés, conversions Ed25519/X25519, VDF (`chiavdf`), Reed-Solomon, agilité post-quantique |
| **Protocole** (`impl/protocol`) | **Rust**, dépend de `impl/core` | Logique de protocole partagée par le Nœud et le Connecteur, sans I/O réseau : types FlatBuffers générés, enveloppes DHT signées, règles de vérification, TTL et lissage, tags `key_algorithm`, séquences (`EmergencyEntry`, `migration_pointer`) |
| **Nœud** (`impl/node`) | **Rust**, lie `impl/core` et `impl/protocol` | Démon hébergeur : réseau, stockage physique, PoS, dashboard Nœud |
| **Connecteur** (`impl/connector`) | **Rust**, lie `impl/core` et `impl/protocol` | Moteur client : DHT, système de fichiers, lecteur monté (WinFsp / FUSE), écriture différée, API locale |
| Dashboards | **TypeScript**, fichiers statiques | Interface uniquement, servie par le binaire Nœud ou Connecteur ; aucun runtime JavaScript à l'exécution |

## Pourquoi un noyau et un crate protocole partagés

Principe du projet : **aucun fait à deux endroits**. Deux implémentations
d'un même KDF, d'un même code correcteur ou d'une même règle de
vérification d'enveloppe divergent silencieusement — la classe de bug la
plus difficile à détecter en revue. Le Nœud et le Connecteur étant tous
deux en Rust, ils **lient le même code** :

- `impl/core` : ce qui est mathématique et pur (primitives, dérivations,
  VDF, erasure coding). Aucune dépendance à `impl/protocol`.
- `impl/protocol` : ce qui est protocolaire mais commun aux deux rôles
  (formats sur le fil et règles d'acceptation d'une entrée DHT, par
  exemple). Il ne fait pas d'I/O : les adaptateurs réseau et disque vivent
  dans `impl/node` et `impl/connector`.
- Ce qui n'est propre qu'à un rôle reste dans son composant (stockage
  physique et PoS pour le Nœud ; lecteur monté et écriture différée pour le
  Connecteur).

Les types générés par `flatc` depuis `schemas/**/*.fbs` sont émis une fois,
en Rust, dans `impl/protocol` ; la génération TypeScript n'est plus
nécessaire.

## Pourquoi Rust

- **Adéquation à l'IA** : le compilateur Rust (emprunt, durées de vie,
  exhaustivité du pattern matching) constitue une boucle de rétroaction
  serrée pour un agent — une classe entière de bugs (data races,
  use-after-free, désérialisation FlatBuffers mal bornée) est rejetée avant
  l'exécution.
- **Stabilité** : garanties de compatibilité par édition, écosystème mature
  sur les briques nécessaires, `rust-libp2p` utilisé en production sur des
  systèmes comparables.
- **Maintenabilité** : `cargo clippy` + `rustfmt` imposent un style uniforme.
- **Rapidité** : pas de ramasse-miettes (latence prévisible pour les
  challenges PoS à [timeout strict](../docs/05-securite/pos-challenges.md)),
  empreinte mémoire faible (NAS, Raspberry Pi —
  [`deploiement.packaging`](../docs/07-deploiement/packaging.md)).
- **Un seul langage côté moteur** : le Connecteur a besoin de `chiavdf` en
  génération et en vérification ; en Rust il le lie directement, sans
  `bun:ffi` ni binaire sidecar.

### Alternative envisagée et écartée : Go pour le Nœud

`go-libp2p` est l'implémentation libp2p de référence et la courbe
d'apprentissage est plus douce, mais le VDF de Wesolowski exige de
l'arithmétique de groupe de classes pour laquelle l'écosystème Go n'offre
rien de mûr : il aurait fallu des bindings CGo vers une bibliothèque C++ de
toute façon. Rust a un écosystème de liaison FFI plus discipliné pour ce
cas précis.

## Bibliothèques spécifiques à ne PAS réimplémenter

Deux endroits de la spec sont assez subtils pour que la bonne décision soit
de **lier une bibliothèque auditée** plutôt que d'écrire l'arithmétique :

- **VDF de Wesolowski sur groupe de classes** — lier la crate `chiavdf`
  1.1.14 (bibliothèque C++ du réseau Chia, même construction : discriminant
  négatif, `Cl(Δ)`, preuve de Wesolowski). C'est le **seul prouveur et le
  seul vérificateur** du protocole : aucun vérificateur maison, même « en
  Rust pur » (le vérificateur pur écrit en octobre 2026 pour le pont WASM
  est retiré). Paramètres : [`network.vdf-identity`](../docs/01-network-dht/vdf-identity.md).
- **Reed-Solomon** — la crate `reed-solomon-erasure` (GF(2⁸)).

Le reste (suite symétrique, conversions Ed25519/X25519, wrapping de clés)
est composé à partir de bibliothèques standard, sous réserve de tests sur
les vecteurs des standards concernés (RFC 7748, RFC 8032, RFC 8439,
RFC 5869, RFC 4231, RFC 6234).

## Bibliothèques retenues

| Besoin | Crate |
|---|---|
| Ed25519 / X25519 | `ed25519-dalek`, `x25519-dalek` |
| Suite symétrique — ChaCha20-Poly1305, HKDF-SHA256, SHA-256, HMAC ([`crypto.symmetric-suite`](../docs/03-crypto/symmetric-suite.md)) | `chacha20poly1305`, `hkdf`, `sha2`, `hmac` |
| VDF Wesolowski | `chiavdf` 1.1.14 (feature `vdf` de `impl/core`) |
| Reed-Solomon | `reed-solomon-erasure` |
| Sérialisation | `flatbuffers` = 23.5.26, types générés par `flatc` 23.5.26 (paquet Debian `flatbuffers-compiler`, `impl/protocol/gen.sh`) — les deux versions doivent rester identiques |
| Réseau / DHT | `rust-libp2p` (Kademlia), Nœud et Connecteur |
| Stockage local (Nœud) | `rusqlite` (WAL) |
| Fichiers creux (Nœud) | `libc` (`fallocate`) |
| Lecteur monté (Connecteur) | backend WinFsp (Windows) puis FUSE (`fuser`) derrière un trait commun — crate WinFsp **à trancher** au démarrage de la tâche |
| API locale HTTP / WebSocket | **à trancher** au démarrage de la tâche (contraintes : liaison `127.0.0.1`, contrôle `Origin`/`Host`, voir [`deploiement.packaging`](../docs/07-deploiement/packaging.md#api-locale)) |

## Contraintes du binding `chiavdf`

Constatées à la lecture de la crate (`lib.rs`) et validées en CI :

- L'interface publique se réduit à `create_discriminant`, `prove` et
  `verify_n_wesolowski`. Ni hash vers forme, ni arithmétique de formes :
  ne pas en écrire à côté.
- La taille du discriminant est plafonnée par la bibliothèque (λ = 1024,
  valeur retenue dans `network.vdf-identity`).
- Les entrées sont à taille fixe. `verify_n_wesolowski` transmet la forme
  de départ à la couche C++ **sans sa longueur** : le wrapper Rust vérifie
  les longueurs (forme 100 o, preuve 200 o, discriminant 128 o) avant tout
  appel, sous peine de lecture hors limites sur une entrée hostile.
- Le vérificateur recalcule `Δ` à partir de l'**identité marquée**
  (`key_algorithm ‖ clé`) ; il n'accepte jamais un `Δ` fourni.
- Tests rapides sur fixtures `T = 100` versionnées avec leur provenance :
  [`network.vdf-verifier-pure`](../docs/01-network-dht/vdf-verifier-pure.md).

## Environnement de build et CI (`chiavdf`)

La crate compile du C++ par CMake et génère ses bindings avec `bindgen`
(libclang). Plateformes validées en CI (GitHub Actions : `windows-latest`,
`ubuntu-latest`, `ubuntu-24.04-arm`, `macos-latest`) :

| Plateforme | Dépendances de build |
|---|---|
| Linux (x86, ARM) | `cmake`, `libgmp-dev`, `libclang-dev` |
| macOS | `brew install gmp cmake`, avec `CPATH` et `LIBRARY_PATH` pointant vers le préfixe de `gmp` |
| Windows | Visual Studio (MSVC) + `cmake` + LLVM ; `LIBCLANG_PATH` vers le `bin` de LLVM ; **ne pas écraser `INCLUDE`** |

- **Windows : MSVC uniquement.** La crate embarque sa propre MPIR pour
  MSVC ; MinGW est exclu (build impossible, prouveur bloqué avec une
  bibliothèque de substitution).
- **Validé en local le 2026-11-20** (Windows 11, VS 2022, CMake 4 via
  winget, LLVM 23) : `cargo test --features vdf` de `impl/core` passe
  nativement ; preuve `T = 5 400 000` en ≈ 110 s. Les tests et binaires
  ont besoin des DLL `mpir*.dll` de chiavdf (`mpir_gc_x64/`) dans le `PATH`
  ou à côté de l'exécutable — `bash impl/package-windows.sh` produit
  `impl/dist/windows/` (Nœud, Connecteur, DLL).
- **Builds locaux** : un conteneur Docker Linux (`cmake`, `libgmp-dev`,
  `libclang-dev`, toolchain Rust) suffit pour compiler et tester
  `impl/core` avec la feature `vdf` hors de la CI.
- **Exécution sous Windows** : `mpir.dll` et ses variantes par processeur
  à côté du binaire, runtime Visual C++ (`MSVCP140`, `VCRUNTIME140`,
  `VCRUNTIME140_1`). **La licence de MPIR est à faire valider avant toute
  distribution** — elle concerne désormais aussi le binaire Connecteur.
- Plus de cible `wasm32` : la feature `wasm` de `impl/core` et le harnais
  `wasm-bindgen-test` sont à retirer (tâche `network.vdf-verifier-pure`).

## Exécutables et lecteur monté

- `s3m-node` (`impl/node`, `init <dir>` puis `<config.json>`) ; image
  Docker : `docker build -f impl/node/Dockerfile -t s3m-node impl`
  (feature `vdf`, réseau de l'hôte : l'API du dashboard n'écoute que
  `127.0.0.1`).
  Vérifiée le 2026-11-20 : preuve VDF en ≈ 20 s dans le conteneur, entrée
  Node publiée ; renseigner `public_ip` dans `/data/node.json` après
  `init`. Sous Docker Desktop (Windows, macOS), `--network host` ne relie pas
  le conteneur au poste : le dashboard n'y est joignable que depuis un
  conteneur partageant son réseau (`--network container:<nom>`) ; sur un
  hôte Linux, il l'est depuis l'hôte.
- `s3m-connector` (`impl/connector`) ; lecteur WinFsp derrière la
  feature `mount` : WinFsp installé (exécution) et LLVM pour bindgen
  (compilation, `LIBCLANG_PATH="C:/Program Files/LLVM/bin"`) —
  `cargo build --release --features mount`. La DLL WinFsp est cherchée dans
  `%ProgramFiles(x86)%\WinFsp\bin` (ou `WINFSP_DIR`).
- Réseau du Nœud : une seule pile libp2p (TCP + QUIC sur le même port —
  ouvrir TCP **et** UDP), UPnP actif par défaut (`upnp: false` pour le
  couper), service de relais (`relay_server`, `relay_limits`), relais imposés
  possibles (`relays`). Sous Windows, les connexions sortantes prennent un
  port neuf : le perçage de NAT passe surtout par QUIC.
- Application de barre des tâches `S3m.exe` (feature `tray` du Connecteur :
  `tray-icon`, `tao`, `winreg`, notifications WinRT ; icône intégrée par
  `embed-resource`). Données dans `%APPDATA%\S3m` ; `S3M_HEADLESS=1` : mode
  d'essai sans navigateur ni notification. Icônes régénérables depuis
  `LogoS3M.png` : `python impl/connector/assets/make_icons.py` (Pillow).
- Carte du dashboard Nœud : base de géolocalisation DB-IP « City Lite »
  (≈ 130 Mo, CC BY 4.0) téléchargée par `s3m-node geoip-update
  <data_dir>` (mise à jour mensuelle à relancer) ; sans elle, la carte compte
  tous les points comme non localisés.
- Entrées DHT : le Nœud publie son entrée (preuve VDF calculée une fois,
  `data/vdf_proof.bin`, adresse `public_ip`/`public_port`) ; le Connecteur
  publie son entrée User si `dht_bootstrap` est renseigné (adresse « DHT »
  du dashboard Nœud) et y relit sa racine sur un nouvel appareil.
