> Workflow Cline — invoquer avec `/git-commit.md` (après qu'un id est terminé) ; la Phase 2 (fusion) ne s'exécute que sur demande explicite de l'utilisateur.
> Si une commande de la checklist échoue : afficher les échecs et ARRÊTER le workflow, ne pas continuer.
> Garder l'approbation manuelle activée pour `git push` et `git merge`.


# Discipline git — un id, un commit, une checklist

Ce workflow ne remplace jamais le jugement de l'utilisateur : il refuse de
committer silencieusement un travail incomplet, il ne "corrige" jamais la
checklist en douce pour la faire passer.

## Checklist obligatoire avant TOUT commit (AGENTS.md §3)

Vérifier ces 5 conditions, dans l'ordre, en exécutant réellement les
commandes — jamais en supposant qu'elles passeraient :

1. **Tests verts** : `cargo test` (impl/core, impl/node) ou `bun test`
   (impl/connector) passe entièrement pour le composant touché.
2. **`impl/status.yml` à jour** : l'entrée de l'id concerné a
   `status: done`, `owner` renseigné, `tests:` liste au moins un test réel
   (pas une liste vide).
3. **`manifest.yml` à jour** : le champ `verified_by` de la page docs
   correspondant à cet id a été renseigné.
4. **Doc saine** : `mkdocs build --strict` passe sans erreur.
5. **Périmètre respecté** (AGENTS.md §4) : `git status` ne montre AUCUN
   fichier modifié en dehors du sous-répertoire/des fichiers propres à cet
   id précis. Un fichier partagé modifié (schémas .fbs, impl/core consommé
   par d'autres ids) doit avoir été signalé à l'utilisateur AVANT ce point,
   pas découvert ici.

**Si une seule condition échoue : ne pas committer.** Dire précisément
laquelle manque et proposer de la corriger — ne jamais committer une version
partielle "pour avancer quand même".

## Convention de branche

Une branche par id :
```
git checkout -b feat/<id-avec-tirets-a-la-place-des-points-et-slashes>
```
Exemple : id `crypto.k-attach` → `feat/crypto-k-attach`.

## Message de commit

Format fixe : `impl(<component>): <id> — <résumé court à l'infinitif ou au nom>`

Exemples :
- `impl(core): crypto.keys — Ed25519 to X25519 conversion`
- `impl(core): crypto.k-self — HKDF derivation`
- `impl(node): dht.bootstrap — rendezvous protocol handshake`

**Un id = un commit, toujours** — même si plusieurs ids ont été travaillés
dans la même session, même si les fichiers touchés se ressemblent. C'est ce
qui garde la checklist ci-dessus vérifiable sur un diff propre a posteriori.

## Séquence complète

1. Dérouler la checklist ci-dessus, condition par condition, en montrant le
   résultat de chaque vérification à l'utilisateur (pas juste "checklist OK").
2. `git status` pour lister précisément ce qui a changé.
3. `git add <fichiers exacts du périmètre de cet id>` — jamais `git add .`
   sans avoir validé la liste à l'étape 2.
4. `git commit -m "impl(<component>): <id> — <résumé>"`.
5. `git push -u origin feat/<id>` (première fois sur cette branche) ou
   `git push` (branche déjà suivie).
6. Rapport final : id fermé, nom de la branche, hash du commit, et rappel
   des 5 conditions de la checklist avec leur résultat individuel — jamais
   un simple "c'est fait" sans le détail.

## Cas particulier — plusieurs ids prêts en même temps

Ne jamais les grouper. Répéter la séquence complète une fois par id, dans
l'ordre où `impl/status.yml` les liste, chacun sur sa propre branche et son
propre commit.

## Phase 2 — Fusionner une branche vers main (jamais automatique)

Ce workflow ne fusionne JAMAIS de sa propre initiative, même après un commit
réussi et pushé. La fusion est déclenchée explicitement par l'utilisateur
("merge la branche feat/<id>", "fusionne k-self") — jusque-là, la branche
reste ouverte, et c'est un état normal, pas un travail inachevé.

### Critères avant de fusionner (au-delà de la checklist du commit)

1. **Revue du diff par l'utilisateur** : présenter `git diff main..feat/<id>
   --stat` puis proposer `git diff main..feat/<id>` en entier si demandé.
   Ne jamais fusionner sans que ce diff ait été montré.
2. **Rebase de `main` dans la branche AVANT de fusionner dans l'autre sens** :
   ```
   git checkout feat/<id>
   git fetch origin
   git rebase origin/main
   ```
   Objectif : détecter un conflit avec un autre id fusionné entre-temps
   (pertinent si plusieurs branches touchent `impl/core`, consommé par
   plusieurs ids en parallèle). Un conflit ici est un signal à traiter, pas
   à résoudre à l'aveugle — si la résolution n'est pas évidente, s'arrêter
   et demander arbitrage à l'utilisateur (même logique que SPEC_GAPS.md).
3. **Re-passer la checklist complète après ce rebase**, pas se fier au
   résultat obtenu au moment du commit initial : `cargo test` (ou
   `bun test`) et `mkdocs build --strict`, sur le code rebasé. Un id partagé
   modifié depuis (ex. une signature dans `impl/core/src/keys.rs`) peut
   avoir invalidé silencieusement un test qui passait avant.
4. **Fusion avec trace explicite** :
   ```
   git checkout main
   git merge --no-ff feat/<id> -m "Merge feat/<id>: <résumé de l'id>"
   git push
   ```
   `--no-ff` plutôt qu'un fast-forward silencieux : garde un commit de
   fusion identifiable par id dans l'historique de `main`, cohérent avec
   "un id = une unité traçable" déjà appliqué au commit lui-même.
5. **Nettoyage** :
   ```
   git branch -d feat/<id>
   git push origin --delete feat/<id>
   ```

### Ce que ce workflow ne décide jamais seul

- L'ordre de fusion entre plusieurs branches prêtes en même temps (c'est à
  l'utilisateur de choisir, en fonction des dépendances réelles entre ids
  visibles dans `impl/layers.yml`).
- La résolution d'un conflit de rebase non trivial.
- Fusionner une branche dont la checklist du commit initial n'a pas été
  entièrement respectée, même si l'utilisateur insiste — dans ce cas,
  signaler l'écart et demander confirmation explicite avant de continuer.
