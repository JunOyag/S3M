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