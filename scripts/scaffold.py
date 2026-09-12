#!/usr/bin/env python3
"""
scaffold.py
===========
Crée, sous docs/, un stub pour chaque page déclarée dans manifest.yml qui
n'existe pas encore. Ne réécrit JAMAIS un fichier déjà présent : les pages
pivots rédigées intégralement (voir README.md § "Fichiers pivots") ne sont
donc jamais écrasées par un nouveau passage de ce script.

Usage:
    python scripts/scaffold.py
"""
from __future__ import annotations
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "manifest.yml"
DOCS = ROOT / "docs"

SCHEMA_TEMPLATE = """---
id: {id}
kind: schema
title: "{title}"
section: "{section}"
fbs_source: "{fbs}"
status: stub
verified_by: []
---

# {title}

> **Statut : stub** — page à finaliser. Gabarit de référence :
> `docs/02-schemas/dispersal/BlockEntry.md` (page pivot entièrement rédigée).

Table source : `{fbs}` — **ne pas retaper les champs ici**, ils sont générés
automatiquement depuis le `.fbs` et inclus ci-dessous par snippet.

## Champs

```
--8<-- "{table_md}"
```

<!-- Rédiger ici 2-4 phrases de contexte métier propres à cette table :
     pourquoi elle existe, qui l'écrit/la lit, invariants notables.
     Ne pas dupliquer une description déjà présente sur une autre page —
     y renvoyer par lien à la place. -->
"""

NARRATIVE_TEMPLATE = """---
id: {id}
kind: narrative
title: "{title}"
section: "{section}"
status: stub
verified_by: []
---

# {title}

> **Statut : stub** — page à finaliser. Gabarits de référence :
> `docs/03-crypto/k-attach.md` (page conceptuelle) ou
> `docs/04-protocols/dispersion-transactionnelle.md` (page protocole avec étapes).

<!-- Rédiger ici le contenu narratif correspondant à {section} de la
     spécification d'origine (ST-P2P-STORAGE-2026-V2.md). Référencer les
     schémas et autres pages via leur id (voir manifest.yml, champ `refs`)
     plutôt que de recopier leur contenu. -->

## Références

{refs_list}
"""


def main() -> None:
    data = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    pages = {p["id"]: p for p in data["pages"]}

    created, skipped = [], []

    for pid, p in pages.items():
        target = DOCS / p["path"]
        if target.exists():
            skipped.append(p["path"])
            continue

        target.parent.mkdir(parents=True, exist_ok=True)

        if p["kind"] == "schema":
            fbs = p["fbs"]
            fbs_file, table = fbs.split("#")
            # Chemin RELATIF au base_path "build/schemas" déclaré dans mkdocs.yml
            # (pymdownx.snippets) — ne pas préfixer par "build/schemas" ici,
            # sous peine de double préfixe à la résolution (cf. mkdocs.yml).
            table_md = str(Path(fbs_file).parent.name) + f"/{table}.table.md"
            content = SCHEMA_TEMPLATE.format(
                id=pid, title=p["title"], section=p.get("section", ""),
                fbs=fbs, table_md=table_md,
            )
        else:
            refs = p.get("refs", [])
            if refs:
                refs_list = "\n".join(f"- `{r}` — {pages[r]['title']}" for r in refs)
            else:
                refs_list = "*(aucune pour l'instant)*"
            content = NARRATIVE_TEMPLATE.format(
                id=pid, title=p["title"], section=p.get("section", ""),
                refs_list=refs_list,
            )

        target.write_text(content, encoding="utf-8")
        created.append(p["path"])

    print(f"[scaffold] {len(created)} fichier(s) créé(s), {len(skipped)} déjà existant(s) (préservé(s)).")
    for c in created:
        print(f"  + {c}")


if __name__ == "__main__":
    main()
