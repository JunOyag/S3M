# Contenu de ce scaffold — tests d'intégration (squelette Phase 0)

À fusionner à la racine du dépôt (ajoute `.claude/skills/integration-test/`
et `tests/integration/`, ne touche à rien d'existant).

## Ce qui est fonctionnel dès maintenant

- `tests/integration/docker-compose.test.yml` — topologie figée (1 Nœud +
  1 Connecteur + 12 partenaires, réseau isolé), mais `build:` pointe vers
  des `Dockerfile` qui n'existent pas encore dans `impl/node`/`impl/connector`.
- `tests/integration/run_scenario.py` — flux d'orchestration stable
  (up → inject → attendre → assert → down → rapport).
- 7 scénarios stubs, un par ligne pertinente du tableau §6, chacun avec
  `SPEC_REF`/`EXPECTED` déjà rédigés (donc déjà utile en lecture, même
  avant toute implémentation) et `inject()`/`assert_recovery()` en
  `NotImplementedError` avec le TODO exact de ce qu'il faudra faire.

## Ce qu'il reste à faire, dans l'ordre, une fois en Phase 2+

1. `impl/node/Dockerfile` et `impl/connector/Dockerfile`.
2. Une interface minimale d'automatisation côté Connecteur/Nœud (CLI ou
   HTTP local) — `run_scenario.py` et les scénarios en ont besoin pour
   déclencher des écritures/lectures et lire l'état sans passer par
   l'interface WebDAV/dashboard destinée à un humain.
3. Compléter `inject()`/`assert_recovery()` scénario par scénario, dans
   l'ordre du tableau §6 (le plus simple d'abord :
   `node_temporarily_unavailable` avant `node_lost_no_compromise`).
4. Chaque scénario complété doit être référencé dans le `verified_by` de
   sa page `docs/06-procedures-secours/` correspondante (convention déjà
   posée dans le projet), avec l'id `integration/<nom-du-fichier>`.

## Utilisation du skill

Une fois Phase 1 (réseau de base) `done` dans `impl/status.yml`, invoquer
`/integration-test` dans Claude Code, ou décrire directement le scénario à
tester — le skill vérifie lui-même le prérequis de phase avant de lancer
quoi que ce soit.
