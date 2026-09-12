#!/usr/bin/env python3
"""
init_impl_status.py
====================
Crée (une seule fois — n'écrase jamais un fichier existant) impl/status.yml :
le suivi de l'état d'IMPLÉMENTATION (code), séparé du `status:` en
frontmatter des pages (qui suit l'état de la DOC, déjà géré par
`scripts/status.py`). Un agent qui termine une tâche met à jour son entrée
ici, jamais dans manifest.yml (qui reste le plan stable, non modifié par le
chantier de code).

Usage:
    python3 scripts/init_impl_status.py
"""
from __future__ import annotations
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "manifest.yml"
OUT = ROOT / "impl" / "status.yml"

EXCLUDE = {"overview.architecture", "overview.glossary", "secours.reference-consolidee"}


def main() -> None:
    if OUT.exists():
        print(f"[init_impl_status] {OUT} existe déjà — rien à faire (édition manuelle par les agents).")
        return

    data = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    pages = [p for p in data["pages"] if p["id"] not in EXCLUDE]

    entries = {}
    for p in sorted(pages, key=lambda p: p["id"]):
        entries[p["id"]] = {
            "kind": p["kind"],           # schema | narrative — pour resituer rapidement
            "status": "not_started",     # not_started | in_progress | blocked | done
            "owner": None,                # nom de l'agent/équipe assigné
            "tests": [],                   # identifiants de tests, recopiés vers manifest.yml verified_by une fois écrits
            "notes": "",
        }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    header = (
        "# impl/status.yml — suivi d'implémentation (code), séparé de manifest.yml (doc).\n"
        "# Généré une fois par scripts/init_impl_status.py, puis édité manuellement par\n"
        "# les agents au fil du chantier. Ne pas régénérer après le lancement du projet\n"
        "# (écraserait la progression) — le script refuse d'écraser un fichier existant.\n\n"
    )
    OUT.write_text(header + yaml.dump({"entries": entries}, allow_unicode=True, sort_keys=False), encoding="utf-8")
    print(f"[init_impl_status] {len(entries)} entrée(s) initialisée(s) dans {OUT}")


if __name__ == "__main__":
    main()
