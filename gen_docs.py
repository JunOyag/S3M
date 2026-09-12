"""
gen_docs.py — hook mkdocs-gen-files, exécuté à chaque `mkdocs build`/`mkdocs serve`.

Responsabilités (toutes pilotées par manifest.yml, source de vérité unique) :
  1. Régénérer build/schemas/**/*.schema.json et *.table.md depuis les .fbs
     (scripts/fbs_to_jsonschema.py) — jamais fait à la main.
  2. Construire docs/objects/index.json : id -> {path, kind, title, section}
     pour toute la base. Sert de table de résolution pour les cross-refs
     `[[id]]` utilisées dans les pages narratives (voir docs_macros / autorefs).
  3. Injecter, pour CHAQUE page déclarée dans manifest.yml, une section
     générée "## Référencé par" listant les pages qui la référencent — calculée
     par inversion du graphe `refs`, donc jamais tenue à jour manuellement.
  4. Faire échouer le build si manifest.yml référence un id inexistant, ou si
     un fichier .md déclaré est absent (garde-fou anti-dérive doc/code).

Ce script ne réécrit PAS le contenu rédigé des pages : il ne fait qu'ANNEXER
un bloc généré (délimité par des marqueurs) en fin de fichier. Toute édition
manuelle à l'intérieur du bloc généré serait écrasée au prochain build —
c'est voulu : ce bloc n'est source de vérité nulle part ailleurs que dans
manifest.yml.
"""
from __future__ import annotations
import json
import subprocess
import sys
from pathlib import Path

import mkdocs_gen_files
import yaml

ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "manifest.yml"
DOCS = ROOT / "docs"

GENERATED_MARK_START = "<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->"
GENERATED_MARK_END = "<!-- GENERATED:BACKLINKS:END -->"


def load_manifest() -> dict:
    data = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    pages = {p["id"]: p for p in data["pages"]}
    return pages


def validate(pages: dict) -> None:
    errors = []
    for pid, p in pages.items():
        for ref in p.get("refs", []):
            if ref not in pages:
                errors.append(f"[{pid}] référence l'id inconnu '{ref}' (manifest.yml)")
        target = DOCS / p["path"]
        if not target.exists():
            errors.append(f"[{pid}] fichier déclaré absent : {p['path']} "
                           f"(lancer scripts/scaffold.py)")
    if errors:
        for e in errors:
            print(f"ERREUR manifest.yml: {e}", file=sys.stderr)
        raise SystemExit(f"{len(errors)} incohérence(s) manifest.yml — build arrêté.")


def build_backlinks(pages: dict) -> dict:
    backlinks = {pid: [] for pid in pages}
    for pid, p in pages.items():
        for ref in p.get("refs", []):
            backlinks[ref].append(pid)
    return backlinks


def write_objects_index(pages: dict) -> None:
    index = {
        pid: {
            "path": p["path"],
            "kind": p["kind"],
            "title": p["title"],
            "section": p.get("section", ""),
        }
        for pid, p in pages.items()
    }
    with mkdocs_gen_files.open("objects/index.json", "w") as f:
        json.dump(index, f, indent=2, ensure_ascii=False)


def inject_backlinks(pages: dict, backlinks: dict) -> None:
    for pid, p in pages.items():
        src = DOCS / p["path"]
        text = src.read_text(encoding="utf-8")

        # Retire un éventuel bloc généré précédent (idempotence)
        if GENERATED_MARK_START in text:
            pre, _, rest = text.partition(GENERATED_MARK_START)
            _, _, post = rest.partition(GENERATED_MARK_END)
            text = pre.rstrip() + "\n"

        refs_out = backlinks.get(pid, [])
        block_lines = [GENERATED_MARK_START, "", "## Référencé par", ""]
        if refs_out:
            for r in sorted(refs_out):
                rp = pages[r]
                block_lines.append(f"- [{rp['title']}]({_relative(p['path'], rp['path'])}) — `{r}` ({rp['section']})")
        else:
            block_lines.append("*(aucune page ne référence celle-ci pour le moment)*")
        block_lines += ["", GENERATED_MARK_END, ""]

        final_text = text.rstrip() + "\n\n" + "\n".join(block_lines)
        with mkdocs_gen_files.open(p["path"], "w") as f:
            f.write(final_text)
        mkdocs_gen_files.set_edit_path(p["path"], "../" + str(src.relative_to(ROOT)))


def _relative(from_path: str, to_path: str) -> str:
    import os
    from_dir = Path(from_path).parent
    return os.path.relpath(to_path, start=from_dir).replace("\\", "/")


def main() -> None:
    subprocess.run([sys.executable, str(ROOT / "scripts" / "fbs_to_jsonschema.py")], check=True)

    pages = load_manifest()
    validate(pages)
    backlinks = build_backlinks(pages)
    write_objects_index(pages)
    inject_backlinks(pages, backlinks)


main()
