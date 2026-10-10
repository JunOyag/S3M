> Workflow Cline — invoquer avec `/integration-test.md`.
> Si une étape échoue de façon inattendue : afficher le détail et arrêter, ne pas contourner.
> Garder l'approbation manuelle pour toute commande `docker` et tout `git push`/`git merge`.


# Tests d'intégration — squelette Phase 2+

Ce workflow ne peut s'exécuter qu'une fois `impl/node` et `impl/connector` ont
une implémentation minimale fonctionnelle (protocole réseau de base, pas
seulement des stubs `todo!()`). Avant toute chose, vérifier ce prérequis.

## Étape 0 — Vérifier que c'est utilisable

Lire `impl/status.yml` : au moins les ids de Phase 1 (réseau/DHT de base,
`impl/layers.yml`) doivent être `done`, pas seulement Phase 0 (crypto pure).
Si ce n'est pas le cas, **s'arrêter et le dire** — ne pas tenter de lancer
le harnais contre du code qui n'existe pas encore, ni bricoler un mock qui
masquerait le vrai état du projet.

## Étape 1 — Construire/rafraîchir la stack de test

```bash
cd tests/integration
docker compose -f docker-compose.test.yml build
```

La stack (`docker-compose.test.yml`) est un réseau Docker **isolé**
(`p2p-test`, driver bridge) : 1 Nœud hébergeur, 1 Connecteur, 12 partenaires
(minimum requis par le protocole lui-même pour disperser une stripe
complète — coef=3, k=4 → 12 blocs de parité, §4.1). **Aucun service ne doit
jamais pointer vers un bootstrap DHT public réel** — vérifier
`docker-compose.test.yml` avant chaque lancement si un agent l'a modifié.

## Étape 2 — Choisir et lancer un scénario

Chaque fichier `tests/integration/scenarios/<nom>.py` correspond à une ligne
du tableau §6 du protocole (`docs/06-procedures-secours/reference-consolidee.md`).
Lancer :

```bash
python3 tests/integration/run_scenario.py <nom-du-scenario>
```

Le runner : (1) démarre la stack propre, (2) exécute `inject()` du scénario
(la panne simulée), (3) attend le délai pertinent, (4) exécute
`assert_recovery()` (les invariants attendus), (5) détruit la stack, (6)
rapporte pass/fail avec le détail de chaque assertion — jamais juste
"pass"/"fail" sans le détail.

## Étape 3 — Cycle anomalie (même discipline que le cycle unitaire)

- **Échec = bug identifiable dans le code de l'id concerné** : corriger,
  relancer le scénario, boucler jusqu'à ce que ça passe — en autonomie,
  sans solliciter l'utilisateur à chaque itération.
- **Échec = comportement attendu ambigu ou non spécifié** (ex. le délai
  exact avant qu'une reconstruction se déclenche n'est pas assez précis
  dans la doc pour écrire une assertion sans hypothèse) : s'arrêter, écrire
  l'entrée dans `impl/SPEC_GAPS.md` (même format qu'ailleurs), attendre
  arbitrage — ne jamais deviner un seuil numérique non documenté.
- **Échec reproductible seulement une fois sur N (flakiness)** : ne pas le
  corriger à l'aveugle par un retry ajouté dans le test. Documenter le taux
  d'échec observé (ex. "3 échecs sur 10 lancements") dans
  `impl/SPEC_GAPS.md` — un test intégration flaky sur un système distribué
  cache presque toujours une vraie race condition, pas un problème de test.

## Garde-fous (impératifs, propres à ce niveau de test)

- **Jamais de fusion automatique** d'une correction issue de ce cycle, même
  si le scénario repasse au vert tout seul — s'arrêter au commit sur
  branche (via le workflow `/git-commit.md`), la fusion reste une décision humaine
  explicite (encore plus vraie ici qu'au niveau unitaire : une correction
  mal comprise sur un système de stockage distribué peut se traduire par de
  la perte de données réelle une fois déployé).
- **Jamais d'injection de panne en dehors de la stack Docker isolée** —
  vérifier `docker-compose.test.yml` avant chaque scénario si un doute
  existe sur son intégrité.
- **Un scénario flaky ne se corrige jamais en ajoutant un sleep/retry**
  sans comprendre la race condition sous-jacente — voir Étape 3.
- Le tableau §6 est la liste de référence des scénarios à couvrir — ajouter
  un nouveau scénario suit le même workflow `new-feature` vu précédemment
  (phase 1 discussion, phase 2 intégration), pas une improvisation directe
  dans `tests/integration/scenarios/`.
