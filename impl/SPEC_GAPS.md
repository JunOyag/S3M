# SPEC_GAPS.md — Ambiguïtés ou incohérences découvertes en implémentant

Voir `AGENTS.md` §5 pour le protocole d'utilisation de ce fichier : un
agent qui rencontre un cas non couvert par `docs/` ajoute une entrée ici et
attend l'arbitrage de l'orchestrateur — il ne comble jamais le vide par une
improvisation silencieuse.

Format d'entrée :

```markdown
## <id concerné> — <titre court>
**Constat** : ...
**Question** : ...
**Impact si non résolu** : ...
**Résolution** : *(rempli par l'orchestrateur une fois tranché, avec la
référence du commit qui met à jour docs/ en conséquence)*
```

---

## crypto.k-attach — Chemin de dérivation BIP-39 → graine Ed25519 (32 octets)

**Constat** : `docs/03-crypto/k-attach.md` (et la note « seed BIP-39 » de sa
section Dérivation) suppose des identités Ed25519 de 32 octets dérivées d'une
seed BIP-39, mais aucune page `docs/` ne fixe le chemin de dérivation exact
(SLIP-0010 Ed25519 ? HKDF-SHA-512 ? autre ?), ni le préfixe de classe, ni le
chemin de nœud utilisé.

**Question** : quel chemin standard retenir pour aller de la phrase mnémonique
BIP-39 aux graines `priv_user` / `priv_node` de 32 octets ?

**Impact si non résolu** : **non bloquant** pour `impl/core` — les fonctions de
Phase 0 prennent la graine 32 octets en entrée, quelle que soit sa provenance.
À trancher avant l'implémentation de la génération d'identités côté Connecteur
et de `crypto.k-self` (récupération depuis la seed), sous peine de divergences
inter-implémentations sur la dérivation elle-même.

**Résolution** : tranché par l'orchestrateur le 2026-10-10 — schéma de
chemins BIP-39 → SLIP-0010 (ed25519, durci, `m/0x703270'/{0'|1'|2'}/<index>',
passphrase vide par défaut). Commit : a0dd36b (branche
`docs/identity-derivation`, doc seule — séparée de `feat/crypto-k-attach`
par la règle « une branche, un id »).


## crypto.master-key-chain — Chemin de dérivation de `master_key[version]`

**Constat** : `crypto.master-key-chain` promet qu'après une rotation, la
clé maîtresse est `mathématiquement indépendante` de l'ancienne, mais
aucune page ne dit d'où dérive `master_key[version]`. Avec le schéma de
chemins `m/<purpose>'/<role>'/<index>'` (`crypto.identity-derivation`),
si `master_key` ne dépend pas de l'index d'identité, l'incrément
d'index ne la change pas et l'indépendance promise ne tient pas.

**Question** : fixer un rôle dédié — piste : `m/<purpose>'/3'/version'`— un index par version de clé maîtresse — ou dériver `master_key[version]`
d'une autre branche ?

**Impact si non résolu** : non bloquant pour `crypto.identity-derivation`
(identités et clé de secours définies sans elle) ; bloquant pour
`crypto.master-key-chain` et toute rotation d'identité User (Phase 0).

**Résolution** : `master_key[version]` = clé enfant SLIP-0010 ed25519 durcie au chemin
`m/0x703270'/3'/version'` (même seed, même passphrase que l'identité). `version` est un
compteur indépendant de l'index d'identité, démarre à 0, borné par `uint16`. Le rôle 3'
ne signe jamais et ne sert à aucun échange DH. `master_key_chain` reste l'unique
mécanisme de lecture des versions antérieures (pas de re-dérivation depuis la seed).
Rotation d'identité seule : pas de nouvelle version ; nouvelle seed ou fuite de
`master_key` : nouvelle version + re-wrap de la chaîne. Documenté dans
`crypto.identity-derivation`, liens depuis `crypto.master-key-chain` et
`securite.incidents-compromissions`. Commit : a0dd36b (branche
`docs/identity-derivation`).

## crypto.k-block / crypto.k-dispersal — Circularité `block_hash` ↔ `K_block` / `K_dispersal_block` et taille utile du bloc

**Constat** : `docs/03-crypto/k-block.md` publie
`K_block = KDF(master_key[version], block_hash, encryption_salt)`, mais
`docs/04-protocols/integrite-lecture.md` décrit le Connecteur qui « recalcule
le hash du contenu (**ciphertext**) reçu et le compare au `block_hash`
attendu » — `block_hash` est donc le hash du **chiffré**, lequel est produit
avec `K_block` lui-même. La formule exige le hash du résultat du chiffrement
qui produit ce résultat : cercle vicieux, impossible à évaluer au moment de
l'écriture d'un bloc. **La même circularité frappe `crypto.k-dispersal`** :
`K_dispersal_block = KDF(K_dispersal_content, block_hash)`
(`docs/03-crypto/k-dispersal.md`) chiffre les blocs internes de l'arbre
d'index « sur le principe de `k-block` » — si `block_hash` y désigne comme en
lecture d'intégrité le hash du chiffré, la dérivation est circulaire pour la
même raison ; la page ne précise d'ailleurs pas quel `block_hash` (clair ?
chiffré ? quel niveau de l'arbre ?). Second constat : `overview.architecture`
fixe une taille
de bloc de 64 KiO avec « en-tête fixe » et `deploiement.formats-serialisation`
un en-tête de 2 octets ; avec la tag AEAD de 16 octets retenue pour
`crypto.symmetric-suite`, la place utile dans les 65 536 octets n'est pas
explicitée — 64 KiO de clair (chiffré à 65 536 + 18 o ?) ou 64 KiO de chiffré
(clair à 65 518 o ?), sachant que `fs.FileBlock` impose un padding « jusqu'à
la taille fixe du bloc » sans préciser de quel côté.

**Question** : (1) remplacer `block_hash` dans les deux formules par un
identifiant **calculable avant chiffrement** — piste : dérivation par **rang**
du bloc (position dans le fichier / niveau de l'arbre d'index) +
`encryption_salt` **neuf à chaque réémission** du
bloc (le salt réelant le hasard du chiffrement et restant porté par
`fs.DirectoryEntry`) ; ou un autre préfixe/champ déjà disponible avant
chiffrement ? Quel `block_hash` exact pour les niveaux de l'arbre d'index
dispersal ? (2) Les 64 KiO désignent-ils le clair ou le chiffré — la tag
(16 o) et l'en-tête (2 o) sont-elles déduites de cette taille, et que vaut
donc la taille utile par bloc ?

**Impact si non résolu** : **bloquant** pour l'écriture de blocs via
`crypto.k-block` **et** `crypto.k-dispersal` (formules publiées non
évaluables) et pour la
composition clé+AEAD de `crypto.symmetric-suite` (AAD, budget de taille du
bloc). Non détecté par les tests existants : `k_block_vectors` et
`k_dispersal_vectors` tiennent `block_hash` en
entrée opaque, la circularité n'apparaît qu'à
l'intégration écriture→lecture.

**Résolution** : tranché par l'orchestrateur le 2026-11-10 — *doc d'abord,
code ensuite*.

1. **Blocs adressés par contenu → chiffrement déterministe.** Le nonce est
   **synthétique** : `nonce = 12 premiers octets de HMAC-SHA256(K_nonce,
   u32(len(AAD)) ‖ AAD ‖ clair)` (encodage canonique, u32 gros-boutiste),
   **stocké en préfixe** de la trame. `K_nonce = HKDF-SHA256(K_enc,
   info = "p2p-storage/synthetic-nonce/v1")` sans sel — règle générique de
   `crypto.symmetric-suite`, appliquée à `K_block` et `K_dispersal_block` ;
   l'AAD porte l'étiquette de contexte de l'usage. Borne de collision du
   nonce synthétique : ~2^48 messages distincts par clé (birthday sur
   96 bits), documentée à côté de la borne 2^32 du nonce aléatoire. La piste
   « dérivation par rang » proposée dans la Question est abandonnée.
2. **Clés indépendantes de `block_hash`** : `K_block = KDF(master_key[version],
   encryption_salt)` (suppression de `block_hash` de l'entrée du KDF) ;
   `K_dispersal_block = KDF(K_dispersal_content, "dispersal-block")`
   (étiquette de domaine fixe). Ni le KDF ni le nonce ne dépendent du hash du
   chiffré → circularité levée ; le `block_hash` (y compris celui des
   niveaux de l'arbre d'index dispersal) est calculé **après** chiffrement,
   comme en lecture d'intégrité.
3. **`encryption_salt` tiré d'un CSPRNG à chaque émission**, conservé dans
   la `WriteQueue` pendant l'attente de synchronisation, puis porté par
   `fs.DirectoryEntry`.
4. **Taille de bloc** : les 64 KiO désignent le bloc **complet** — surcoût
   de trame 30 o (en-tête 2 o + nonce 12 o + tag 16 o), **65 506 o de
   clair** par bloc, padding zéro du clair jusqu'à 65 506 o. Les deux
   sous-questions de taille sont ainsi tranchées.
5. Pages mises à jour par ce même chantier : `docs/03-crypto/k-block.md`,
   `docs/03-crypto/k-dispersal.md`, `docs/03-crypto/master-key-chain.md`,
   `docs/03-crypto/symmetric-suite.md`. **Code à revoir ensuite** :
   `impl/core/src/k_block.rs`, `impl/core/src/k_dispersal.rs`, leurs tests
   et les notes `impl/status.yml` encodent encore l'ancienne formule —
   l'entrée reste ouverte jusqu'à cette passe code (doc d'abord, code
   ensuite).
6. La politique de nonce synthétique est **à faire relire par un
   cryptographe** avant gel (mention également portée dans
   `crypto.symmetric-suite`).

**Commit doc** : `e13b2e7` (branche `docs/symmetric-suite`, doc seule —
code `impl/core` et cette entrée SPEC_GAPS traités séparément, règle
« une branche, un id »).

**Résolution** : *(rempli par l'orchestrateur une fois tranché, avec la
référence du commit qui met à jour docs/ en conséquence)*

## crypto.identity-derivation — Découverte de l'index courant après perte totale

**Constat** : après une perte totale, la seed seule (même avec la bonne
passphrase) ne désigne pas le bon `<index>'` — ni pour le User ni pour le
Node. La restauration à froid (§2.2 / §7.1) suppose pourtant de retrouver
l'identité courante.

**Question** : fixer une règle de restauration — piste : balayage des index
croissants contre la DHT avec une limite d'écart (analogie découverte de
comptes BIP-44) ; côté User, préciser aussi le choix de l'entrée courante
parmi les entrées DHT anciennes (durée de vie 10 ans).

**Impact si non résolu** : non bloquant pour l'intégration documentaire du
schéma de chemins ; bloquant pour le bootstrap à froid complet
(`network.bootstrap`, `deploiement.disaster-recovery`).

**Résolution** : l'index courant est le plus haut index ayant une entrée DHT valide
(signature correcte, durée de vie non expirée). Balayage des index croissants à partir
de 0, arrêt après 20 index consécutifs sans entrée (valeur configurable). Pas de tri par
horodatage : une clé dérivée compromise permet de rafraîchir une ancienne entrée, mais
pas d'en créer une à un index supérieur. Côté User, la version de `master_key` se lit
dans `master_key_chain` (pas de balayage). Côté Node, seules les entrées < 6 mois sont
découvrables (§3.9). Avant de créer l'index k, balayage préalable pour s'assurer qu'aucune
entrée vivante n'y est déjà. Si rien n'est trouvé : message « vérifier la passphrase ».
Limite documentée : si toutes les entrées ont expiré, un index compromis peut être
retrouvé par erreur ; recommander de conserver l'index courant avec la sauvegarde de la
phrase. Documenté dans `crypto.identity-derivation`, liens depuis
`deploiement.disaster-recovery`. Commit : a0dd36b (branche
`docs/identity-derivation`).


## crypto.master-key-chain — Clé de wrap de `wrapped_key` : directe ou KDF ?

**Constat** : l'inventaire du registre des étiquettes KDF
(`crypto.symmetric-suite`) ne trouve **aucune étiquette de dérivation** pour
le wrap de `master_key[version]` : `crypto.master-key-chain` dit seulement
« chiffrée sous la `master_key` courante », `crypto.symmetric-suite` nomme
un domaine **AAD** `« master-key-wrap »` et une « clé de wrap » à usage
unique (nonce nul), sans formule `K_wrap = KDF(…)` ; le stub
`impl/core/src/master_key_chain.rs` (`todo!` — « wrap symétrique sous
new_master_key ») suggère un chiffrement direct sous la clé courante. La
mention `master-key-wrap/v1` n'apparaît nulle part dans `docs/`.

**Question** : le wrap est-il un AEAD **direct** sous `master_key[version]`
(donc sans étiquette KDF, `master-key-wrap` restant une simple étiquette
AAD) — ou faut-il une dérivation du type
`K_wrap = KDF(master_key[version], "master-key-wrap/v1")`, à ajouter au
registre de `crypto.symmetric-suite` ?

**Impact si non résolu** : contournable — le registre reste tel quel et le
stub `rewrap_chain_on_rotation` est de toute façon `todo!` ; bloquant pour
la passe code de `crypto.master-key-chain` (impossible d'implémenter un
wrap sans savoir s'il y a un KDF intermédiaire).

**Résolution** : tranché par l'arbitre — dérivation intermédiaire, pas de
chiffrement direct. La clé de wrap est une **dérivée HKDF-SHA256** ajoutée
au registre des étiquettes de `crypto.symmetric-suite` comme 13ᵉ étiquette :

```
K_wrap = HKDF-SHA256(ikm = master_key[version_courante], salt = ∅,
                      info = encodage canonique("p2p-storage/master-key-wrap/v1"
                                                ‖ u16(version_wrappée)
                                                ‖ u16(version_courante)))
```

Le préfixe fixe `p2p-storage/master-key-wrap/v1` est l'**étiquette** ; les
deux `u16` (version wrappée, version courante) portés en `info` garantissent
l'unicité par couple de versions. Chiffrement : **ChaCha20-Poly1305**, clé à
usage unique → nonce nul, trame `chiffré ‖ tag`, `wrapped_key = 48 o` (32 o
chiffrés ‖ 16 o tag). `AAD = en-tête (2 o) ‖ "master-key-wrap" ‖
u16(version_wrappée) ‖ u16(version_courante)` — un wrap ne se transplante
pas d'une version à une autre. `crypto.master-key-chain` renvoie à cette
règle pour l'étape « déchiffrer `wrapped_key` ». Commit doc : `dd08775`
(branche `docs/symmetric-suite`).


## network.vdf-identity — Dérivation de Δ : λ = 2048 bits (spec) vs plafond 1024 bits de chiavdf

**Constat** : `docs/01-network-dht/vdf-identity.md` (§ « Setup ») fixe
λ = 2048 bits (« plus petit nombre premier `p > 2^λ` »), soit `|Δ| ≥ 2048
bits`. La bibliothèque imposée (CLAUDE.md règle 5, `impl/TECH_STACK.md`) — la
crate `chiavdf` 1.1.14, bindings officiels du projet Chia — plafonne les
discriminants à **1024 bits** : `#define BQFC_MAX_D_BITS 1024` dans `bqfc.h`,
`CreateDiscriminant` refuse `length > 1024`, `bqfc_serialize`/`bqfc_deserialize`
échouent au-delà, et le vérificateur (`IsDiscSizeBitsInRange`) rejette toute
preuve dont `disc_size_bits > 1024` — un `prove(..., 2048, T)` échoue à la
désérialisation et le `verify` correspondant renvoie toujours `false`. Deux
écarts de formulation en sus, à trancher dans la même passe : (a) l'instance
chiavdf de la procédure (`HashPrime`) ne cherche pas « le plus petit premier »
mais le premier candidat d'une **chaîne de SHA-256** du seed incrémenté qui
passe le test de primalité, avec masque de bits {0, 1, 2, λ−1} (donc
`p ≡ 7 mod 8` ⇒ `p ≡ 3 mod 4` conforme, et `p ≥ 2^(λ−1)` au lieu de
`p > 2^λ`) ; (b) la page ne nomme pas le hash de cette dérivation (SHA-256 du
suite `crypto.symmetric-suite` en toute vraisemblance — à confirmer par la doc).

**Question** : (1) λ = 1024 bits (paramètres Chia retenus en production) ou
λ = 2048 bits — auquel cas une fourche/extension de chiavdf avec
`BQFC_MAX_D_BITS` porté ≥ 2048 est nécessaire (modification d'une bibliothèque
auditée, décision à prendre en connaissance de cause) ; (2) valider `HashPrime`
(SHA-256 incrémenté, masque {0, 1, 2, λ−1}) comme instance de la phrase « en
partant du hash d'une chaîne fixe publique et en incrémentant », ou exiger une
autre procédure ; (3) confirmer SHA-256 comme hash de cette dérivation et
reformuler `p > 2^λ` si nécessaire.

**Impact si non résolu** : **bloquant** pour `network.vdf-identity` —
`DISCRIMINANT_BITS` est une constante de protocole partagée par générateurs et
vérificateurs ; l'implémenter « à 1024 quand même » (ou « à 2048 avec un
patch maison ») serait un choix de protocole improvisé (AGENTS.md §5).

**Résolution** (orchestrateur, 17/10/2026) : **λ = 1024 bits** (paramètre Chia en production). Pas de fourche de chiavdf.
- `docs/01-network-dht/vdf-identity.md`, § « Setup » : remplacer « λ = 2048 bits » et « plus petit nombre premier `p > 2^λ` » par la procédure effective de chiavdf : `p` est le premier candidat, dans la chaîne SHA-256 du seed incrémenté, qui passe le test de primalité, avec masque de bits {0, 1, 2, λ−1} (donc `p ≡ 7 mod 8`, donc `p ≡ 3 mod 4`, et `p ≥ 2^(λ−1)`). `Δ = −p`.
- Hash de la dérivation : SHA-256 (d'après l'analyse de `create_discriminant.h` faite par l'agent). Validation empirique : `create_discriminant` reproduit le vecteur Python de référence de la crate (seed `6c3b9aa7…`, 512 bits), et un discriminant de 1024 bits se calcule en ~10 ms.
- `DISCRIMINANT_BITS = 1024` devient une constante de protocole.
- Référence commit docs : `c9f5047`.


## network.vdf-identity — Mapping `x = H(pub_key)` → forme réduite `g ∈ Cl(Δ)`

**Constat** : la page dit seulement que « le challenge `x = H(pub_key)` est
mappé en une forme quadratique `g ∈ Cl(Δ)` » — aucune page `docs/` ne donne la
procédure de mapping (comment dériver une forme réduite `(a, b, c)` de
`SHA-256(pub_key)` ?). Côté binding, l'API C de `chiavdf` exige que `x_s` soit
**déjà** la sérialisation BQFC canonique (taille fixe `BQFC_FORM_SIZE`,
100 octets) d'une forme *réduite* : `prove_wrapper` appelle `DeserializeForm`,
qui lève une exception si les octets ne décodent pas en une forme réduite
(`bqfc_verify_canon` impose `encode(decode(x)) == x`), et le vérificateur
consomme `x_s` à taille fixe sans en accepter d'autre. Un hash brut de
32 octets n'est donc pas une entrée valide, et la façade C de chiavdf n'expose
ni hash-to-form ni réduction/composition de formes (uniquement
`create_discriminant`, `prove`, `verify_n_wesolowski`).

**Question** : définir dans `docs/01-network-dht/vdf-identity.md` la procédure
déterministe exacte `H(pub_key)` → `g` réduit. Pistes à arbitrer : (1)
construction explicite hash → petit module `a` (nombre premier dérivé) puis
résolution de `b² ≡ Δ (mod 4a)` avec `c = (b² − Δ)/(4a)`, forme déjà réduite
sous conditions — arithmétique à écrire hors de chiavdf, à valider
attentivement ; (2) `g = g₀^{H(pub_key)}` par exponentiation de formes via
chiavdf — nécessite d'exposer un helper C++ supplémentaire dans notre propre
wrapper FFI ; (3) retenir la forme identité comme `g` et lier `pub_key`
autrement — écart explicite avec le texte actuel de la page.

**Impact si non résolu** : **bloquant** — sans forme `g` valide, `prove` échoue
dès la désérialisation et aucune preuve d'identité n'est générable ; choisir
une construction non documentée revient à improviser une primitive de groupe
(AGENTS.md §5, CLAUDE.md règle 5).

**Résolution** (orchestrateur, 17/10/2026) : **Δ par identité, forme de départ fixe** (option 3 du constat, retenue en connaissance de cause). Aucune arithmétique de formes écrite hors chiavdf, aucun helper FFI supplémentaire (options 1 et 2 écartées).
- `challenge = SHA-256(pub_key)`, où `pub_key` inclut son tag `key_algorithm` (§8.4).
- `Δ = −HashPrime(challenge, 1024)` (voir entrée précédente).
- Forme de départ `x_s` : l'élément par défaut de chiavdf, sérialisation BQFC de 100 octets `0x08 ‖ 99 × 0x00`. **À confirmer dans `bqfc.h`** : si ce codage désigne l'élément neutre et non la forme génératrice `(2, 1, c)`, la doc doit le nommer exactement ainsi (nos tests sont cohérents avec un départ non trivial : la preuve est valide et non rejouable, mais la nomenclature n'a pas été relue dans la source).
- Génération : `prove(challenge, x_s, 1024, T)` renvoie `y ‖ π`, soit **200 octets**.
- Vérification : le vérificateur **recalcule Δ lui-même** à partir de `pub_key` et ne reçoit jamais Δ du prouveur. Le tuple publié devient `(pub_key, y ‖ π)`.
- `docs/…/vdf-identity.md` : retirer « Δ global, pas un module N par identité » et « Δ n'a pas besoin d'être porté par le tuple » (révision du 05 Sept). Ajouter une ligne d'addendum à l'en-tête de ST-P2P-STORAGE-2026-V2.
- Propriétés validées en CI (vdf-smoke) : preuve rejetée avec une autre identité, octet altéré, mauvais T.
- Référence commit docs : `c9f5047`.


## network.vdf-identity — Valeur de T (durée de la VDF) non fixée

**Constat** : la page affirme que « `Δ`, `T` et la procédure de mise en groupe
sont fixés une fois par la spécification », mais ne donne pour `T` que « ~1
minute sur une machine de référence » — aucun nombre d'itérations ni machine
de référence nommée. Or `T` (`num_iterations` de chiavdf) est une constante de
protocole : générateurs et vérificateurs doivent s'y accorder. Précision utile
: ℓ (le degré de Wesolowski) n'est pas une constante à arbitrer côté binding —
chiavdf le recalcule déterministement à partir de `T`
(`ApproximateParameters`) ; le vérificateur ne prend que `T` et `recursion`
en entrée.

**Question** : fixer `T` en itérations dans la page (piste : 5 400 000 ≈
paramètre de référence Chia pour ~1 minute — à recalibrer selon λ retenu, à
confirmer par mesure, et à documenter avec sa machine de référence).

**Impact si non résolu** : non bloquant pour l'ossature du binding et des
tests de roundtrip (les tests peuvent passer un petit `T` arbitraire), mais
**bloquant pour le gel du protocole** et pour toute revendication de « ~1
minute » ; une valeur choisie dans le code sans arbitrage serait un paramètre
de protocole improvisé.

**Résolution** (orchestrateur, 17/10/2026) : **T = 5 400 000 itérations**, `recursion = 0`.
- Constantes de protocole à inscrire dans `docs/01-network-dht/vdf-identity.md` : `DISCRIMINANT_BITS = 1024`, `T = 5 400 000`, `recursion = 0`.
- Mesures de référence (CI GitHub, médiane de 5 preuves à T = 1 000 000, chiavdf 1.1.14, détail dans `calibration-T-vdf.xlsx`) :
  Linux ARM Neoverse-N2 175 606 it/s, soit 31 s ; Linux x86 Xeon Platinum 8573C 131 254 it/s, soit 41 s ; macOS M1 virtuel 124 828 it/s, soit 43 s ; Windows AMD EPYC 7763 65 068 it/s, soit 83 s.
- Le texte « ~1 minute sur une machine de référence » devient : « de l'ordre de 30 s à 1,5 min selon la plateforme (mesures ci-dessus) ». Aucune machine unique n'est désignée comme référence : les durées sont données par plateforme.
- Limites documentées dans la page : une seule série de mesures par plateforme, sur des runners cloud partagés ; écart Windows ≈ 2× non isolé (MPIR/MSVC contre GMP) ; Raspberry Pi non mesuré.
- Critères de réexamen : mesure sur un vrai Raspberry Pi, ou écart Windows élucidé, ou variation importante lors de runs ultérieurs. Tout changement de T invalide les identités déjà générées (le vérificateur utilise la valeur de protocole), donc il passe par une version de spécification.
- Référence commit docs : `c9f5047`.


## network.vdf-identity — Vérification WASM promise par TECH_STACK et outillage de build du binding

**Constat** : (1) `impl/TECH_STACK.md` (table « Bibliothèques ») promet le VDF
« via WASM — vérification uniquement » pour le Connecteur, mais la crate
`chiavdf` 1.1.14 compile du C++/GMP via CMake et ne peut pas produire
d'artefact `wasm32-unknown-unknown` (la cible WASM de `impl/core` /
`impl/connector`) — l'ajout de la dépendance sans condition ferait échouer le
build `--features wasm`. (2) Sur la machine de développement, l'outillage
nécessaire au build **natif** de la crate est absent : `cmake` (invoqué par
`build.rs`), un compilateur C++ (la crate lie `mpir.lib` MSVC sous Windows —
ni Visual Studio/Build Tools, ni MinGW installés), et `libclang` (bindgen
0.72) ; la session ne dispose pas des droits Administrateur pour installer
ces composants (winget présent, mais élévation requise pour ces paquets).

**Question** : (1) côté Connecteur : feature-gating
`cfg(not(target_arch = "wasm32"))` en attendant, quelle solution finale —
vérification déléguée à un pair Nœud, compilation emscripten/wasi de chiavdf,
autre ? — à arbitrer et à refléter dans `impl/TECH_STACK.md` ; (2) qui installe
l'outillage natif (cmake + toolchain C++ compatible mpir + LLVM/libclang) sur
la machine de build, et avec quels droits ?

**Impact si non résolu** : (1) **bloquant** pour la vérification VDF côté
Connecteur (TECH_STACK, section « Noyau partagé »), contournable en Phase 0
par un gating natif — à documenter alors dans la page et le TECH_STACK ;
(2) **bloquant** dès la première compilation de `chiavdf` — aucune passe code
ni test vert `cargo test` possible tant que l'outillage manque, le binding
restant le seul chemin autorisé (CLAUDE.md règle 5).

**Résolution** (orchestrateur, 17/10/2026) : **vérification native, sans WASM**.
- Connecteur : chiavdf natif par plateforme, via `bun:ffi` ou binaire sidecar. `impl/TECH_STACK.md` : retirer « via WASM ». Gating `cfg(not(target_arch = "wasm32"))` pour la feature `wasm` jusqu'à nouvel ordre.
- Outillage : la crate n'est supportée sous Windows qu'avec MSVC (elle embarque `mpir_gc_x64`). MinGW est exclu : le build exige un `mpir` MSVC, et le prouveur reste bloqué sous MinGW avec un contournement de bibliothèque. Les builds et tests de cet id tournent donc **en CI** (validé : windows-latest, ubuntu x86 et ARM, macOS).
- Dépendances de build : Linux `cmake libgmp-dev libclang-dev` ; macOS `brew install gmp cmake` avec `CPATH` et `LIBRARY_PATH` vers le préfixe gmp ; Windows MSVC + cmake + LLVM, `LIBCLANG_PATH=C:\Program Files\LLVM\bin`, sans surcharge de `INCLUDE`.
- Exécution sous Windows : copier à côté du binaire `mpir.dll` **et** ses variantes CPU (`mpir_*.dll`), et exiger le runtime Visual C++ (MSVCP140, VCRUNTIME140, VCRUNTIME140_1). **Licence de MPIR à faire valider** avant distribution.
- Garde-fous du wrapper Rust : `verify_n_wesolowski` transmet `x_s` sans sa longueur à la couche C++. Le wrapper doit imposer `x_s.len() == 100`, `proof.len() == 200`, `discriminant.len() == 128` avant tout appel.
- À ajouter aux tests : preuve vide ou tronquée, octets aléatoires, `T = 0`, `T = u64::MAX`, `recursion ≠ 0`, avec borne de temps. Les négatifs actuels (octet altéré, mauvais T, autre identité) passent tous.
- Référence commit docs : `c9f5047`.
