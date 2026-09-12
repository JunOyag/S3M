#!/usr/bin/env python3
"""
status.py
=========
Rapport d'avancement de la rédaction, basé sur le champ `status:` en
frontmatter de chaque page (stub | draft | final) et sur le graphe `refs`
de manifest.yml (pour prioriser).

Usage:
    python3 scripts/status.py            # rapport complet
    python3 scripts/status.py --todo     # uniquement la liste des stubs, triée
"""
from __future__ import annotations
import collections
import re
import sys
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "manifest.yml"
DOCS = ROOT / "docs"

FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---", re.DOTALL)


def read_status(md_path: Path) -> str:
    if not md_path.exists():
        return "missing"
    text = md_path.read_text(encoding="utf-8")
    m = FRONTMATTER_RE.match(text)
    if not m:
        return "no-frontmatter"
    fm = yaml.safe_load(m.group(1)) or {}
    return fm.get("status", "unknown")


def main() -> None:
    data = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    pages = {p["id"]: p for p in data["pages"]}

    backlinks = collections.Counter()
    for p in pages.values():
        for r in p.get("refs", []):
            backlinks[r] += 1

    statuses = {pid: read_status(DOCS / p["path"]) for pid, p in pages.items()}
    counts = collections.Counter(statuses.values())

    todo_only = "--todo" in sys.argv

    if not todo_only:
        print("=== Avancement ===")
        for status in ("draft", "final", "stub", "missing", "no-frontmatter", "unknown"):
            if counts.get(status):
                print(f"  {status:>15} : {counts[status]:3d}")
        total = len(pages)
        done = counts.get("draft", 0) + counts.get("final", 0)
        print(f"  {'TOTAL':>15} : {total:3d}   ({done}/{total} rédigées, {100*done//total}%)")
        print()

    remaining = [
        (backlinks[pid], pid, p)
        for pid, p in pages.items()
        if statuses[pid] not in ("draft", "final")
    ]
    remaining.sort(key=lambda t: (-t[0], t[1]))

    print("=== Stubs restants, par priorité (nb de pages qui les référencent) ===")
    for n, pid, p in remaining:
        print(f"  [{n:2d}]  {pid:35s} {p['path']}")


if __name__ == "__main__":
    main()
