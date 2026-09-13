---
name: new-feature
description: Cadre la discussion d'une nouvelle fonctionnalité du protocole P2P-Storage (ST-P2P-STORAGE-2026-V2) puis l'intègre proprement dans manifest.yml, schemas/*.fbs, docs/, impl/layers.yml et impl/status.yml. Utilise ce skill dès que l'utilisateur veut ajouter, étendre, ou même juste discuter d'une nouvelle fonctionnalité du protocole ou de sa doc-as-code — même si la demande ressemble à une simple question exploratoire plutôt qu'à un ordre d'intégration explicite. Ne jamais éditer schemas/, docs/, manifest.yml, impl/layers.yml ou impl/status.yml pour une nouvelle fonctionnalité sans passer par ce skill.
---

# New Feature — cadrage puis intégration

Ce skill a deux phases **strictement séparées**. Ne jamais passer à la phase 2
sans confirmation explicite de l'utilisateur à la fin de la phase 1 — une
réponse ambiguë se clarifie, elle ne s'interprète pas comme un feu vert.

## Phase 1 — Discussion (zéro édition de fichier)

Objectif : transformer une idée informelle en décision précise et sans
ambiguïté, AVANT de toucher le moindre fichier.

1. **Comprendre l'intention.** Que doit faire la fonctionnalité ? À quel(s)
   mécanisme(s) existant(s) se rattache-t-elle ? Chercher dans `manifest.yml`
   et `docs/` les ids déjà proches (par mot-clé, par section) avant de
   supposer qu'il faut créer du neuf — une extension d'id existant est
   presque toujours préférable à un id parallèle qui redit la même chose.
2. **Creuser les cas limites**, sur le même registre que le reste du
   protocole (il ne s'arrête jamais à l'heureux chemin) : quelle clé de
   chiffrement est en jeu (§3.8) ? quel régime d'expiration/republication
   (§3.9) ? qui écrit, qui lit, qui ne doit structurellement rien pouvoir
   déchiffrer ? comment ça interagit avec le troc 1:1, la migration de nœud,
   le PoS, l'écriture hors-ligne ? Poser ces questions explicitement à
   l'utilisateur plutôt que de supposer une réponse.
3. **Vérifier la cohérence avec les règles déjà posées** : évolution
   additive-only des schémas (§3.5), séparation stricte des clés (§3.8), SPOF
   assumé en écriture confirmée (§3.12), portée du troc au niveau
   Nœud↔Partenaire (§3.3)... Si la fonctionnalité proposée contredit une de
   ces règles, le dire explicitement — ne jamais la contourner en silence.
4. **Produire un résumé structuré** (pas encore un patch) :
   - id(s) proposé(s) et où ils vivent (nouvelle page docs/ ? nouvelle table
     .fbs ? extension d'une table existante ?)
   - composant concerné (`core` / `node` / `connector`)
   - phase `impl/layers.yml` visée et dépendances
   - refs vers les ids existants pertinents
5. **Attendre une confirmation explicite** de l'utilisateur sur ce résumé
   avant de passer à la phase 2.

## Phase 2 — Intégration mécanique (une fois confirmé)

Référence : `README.md` section "Ajouter une nouvelle page", `AGENTS.md`, et
la règle additive-only §3.5 du protocole. Appliquer dans cet ordre :

1. **`manifest.yml`** : ajouter la/les entrée(s) (`id`, `kind`, `path`,
   `section`, `refs`) déduites de la phase 1.
2. **Structure de données** : si la fonctionnalité en introduit une, éditer
   le `.fbs` concerné — jamais le `.md` ou le `.schema.json` généré. Si
   c'est une extension d'une table déjà consommée par du code (vérifier
   `impl/status.yml` : status `in_progress` ou `done` pour un id qui en
   dépend), respecter l'additive-only strictement — champ ajouté avec valeur
   par défaut, rien supprimé ni renommé. Si l'additive-only s'avère
   impossible pour ce que demande la fonctionnalité, **s'arrêter et le
   signaler** plutôt que de casser la règle silencieusement.
3. `python3 scripts/scaffold.py` — génère le(s) stub(s) `docs/` manquant(s).
4. **Rédiger le stub** en citant les ids existants pertinents (refs) plutôt
   qu'en redécrivant leur contenu — le principe "un fait, un seul endroit"
   s'applique à ce que vous écrivez autant qu'à ce qui existait déjà.
5. `mkdocs build --strict` — doit passer avant de continuer. Une erreur ici
   se corrige immédiatement, on ne passe pas à la suite avec un build cassé.
6. **`impl/layers.yml`** : placer le(s) nouvel(s) id(s) dans la bonne phase,
   avec ses dépendances déclarées explicitement.
7. **`impl/status.yml`** : AJOUTER MANUELLEMENT une entrée par nouvel id
   (`status: not_started`, `kind`, `owner: null`, `tests: []`, `notes: ""`).
   Rappel impératif : `scripts/init_impl_status.py` refuse d'écraser ce
   fichier une fois qu'il existe — un id oublié à cette étape est un id que
   plus rien ne fera jamais apparaître comme travail à faire.
8. `python3 scripts/plan.py --graph schema` — vérifier qu'aucun cycle n'a été
   introduit par les nouvelles `refs`.
9. **Rapport final** à l'utilisateur : fichiers modifiés/créés, résultat du
   build, et rappel qu'un commit git séparé (un par id, comme pour le reste
   du chantier) reste à faire avant de lancer l'implémentation.

## Garde-fous

- Ne jamais éditer `schemas/**/*.fbs` ou `docs/**/*.md` avant validation
  explicite de la phase 1.
- Ne jamais fusionner les deux phases dans le même échange sans confirmation
  intermédiaire, même si l'intention semble évidente.
- Un conflit détecté avec une règle existante du protocole, à n'importe
  quelle étape : s'arrêter et suivre le protocole `impl/SPEC_GAPS.md` (voir
  `AGENTS.md` §5) plutôt que d'improviser une résolution.
