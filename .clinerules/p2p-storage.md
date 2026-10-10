# Règles permanentes — projet P2P-Storage

Avant toute action, lis AGENTS.md en entier.
- Une session = un id de impl/status.yml ; périmètre = son sous-répertoire (core / node / connector) uniquement.
- Contexte minimal : la page docs/ de l'id, ses refs (manifest.yml), le .fbs si c'est un schéma, sa section de impl/layers.yml.
- Ordre d'implémentation : impl/layers.yml, phase par phase.
- Ambiguïté de spec : écrire dans impl/SPEC_GAPS.md et attendre arbitrage, ne jamais improviser.
- VDF (chiavdf) et Reed-Solomon : à lier, jamais à réimplémenter.
- "Terminé" = AGENTS.md §3 (tests verts, status.yml, verified_by, mkdocs build --strict).
- Un id = un commit ; ne jamais fusionner sans ordre explicite.
- Pour ajouter une fonctionnalité au protocole : utiliser /new-feature.md, ne jamais éditer schemas/, docs/, manifest.yml directement.
- Pour committer : /git-commit.md. Pour les tests d'intégration : /integration-test.md.
