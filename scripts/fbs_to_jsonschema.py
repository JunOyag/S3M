#!/usr/bin/env python3
"""
fbs_to_jsonschema.py
=====================
Convertit les tables FlatBuffers (schemas/**/*.fbs) en JSON Schema
(build/schemas/**/*.schema.json), avec de vrais `$ref` entre tables.

Ce script est la SEULE source qui "lit" le contenu des .fbs. Toute page
Markdown (docs/02-schemas/**) qui a besoin d'afficher la liste des champs
d'une table le fait par inclusion (pymdownx.snippets, balise `--8<--`) du
fragment généré ici (build/schemas/**/*.table.md) — jamais en retapant les
champs à la main. C'est ce qui garantit l'absence de duplication entre le
schéma "code" et sa documentation.

Usage :
    python scripts/fbs_to_jsonschema.py            # écrit dans build/schemas/
    (appelé automatiquement par gen_docs.py au build MkDocs)
"""
from __future__ import annotations
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMAS_SRC = ROOT / "schemas"
BUILD_OUT = ROOT / "build" / "schemas"

# Mapping type FlatBuffers scalaire -> JSON Schema
SCALAR_MAP = {
    "uint8": {"type": "integer", "minimum": 0, "maximum": 255},
    "uint16": {"type": "integer", "minimum": 0, "maximum": 65535},
    "uint32": {"type": "integer", "minimum": 0},
    "uint64": {"type": "integer", "minimum": 0},
    "bool": {"type": "boolean"},
    "string": {"type": "string"},
    "ubyte": {"type": "integer", "minimum": 0, "maximum": 255},
}

TABLE_RE = re.compile(
    r"table\s+(\w+)\s*\{(.*?)\n\}", re.DOTALL
)
FIELD_RE = re.compile(
    r"^\s*(\w+)\s*:\s*(\[?\[?[\w\.]+\]?\]?)\s*;\s*(?://+\s*(.*))?$"
)
DOC_COMMENT_RE = re.compile(r"^\s*///\s?(.*)$")
NAMESPACE_RE = re.compile(r"namespace\s+([\w\.]+)\s*;")


def parse_fbs(path: Path):
    """Retourne (namespace, {table_name: {"doc": str, "fields": [...]}})."""
    text = path.read_text(encoding="utf-8")
    ns_match = NAMESPACE_RE.search(text)
    namespace = ns_match.group(1) if ns_match else "Unknown"

    tables = {}
    lines = text.splitlines()
    pending_doc = []
    i = 0
    while i < len(lines):
        line = lines[i]
        doc_m = DOC_COMMENT_RE.match(line)
        if doc_m:
            pending_doc.append(doc_m.group(1))
            i += 1
            continue
        table_start = re.match(r"\s*table\s+(\w+)\s*\{", line)
        if table_start:
            name = table_start.group(1)
            table_doc = " ".join(pending_doc).strip()
            pending_doc = []
            fields = []
            i += 1
            while i < len(lines) and not lines[i].startswith("}"):
                fline = lines[i]
                fm = FIELD_RE.match(fline)
                if fm:
                    fname, ftype, inline_doc = fm.groups()
                    fields.append({"name": fname, "type": ftype.strip(), "doc": (inline_doc or "").strip()})
                i += 1
            tables[name] = {"doc": table_doc, "fields": fields}
            pending_doc = []
        else:
            if line.strip() and not line.strip().startswith("//"):
                pending_doc = []
        i += 1
    return namespace, tables


def build_index():
    """Construit table_name -> chemin de sortie schema.json, sur tous les .fbs."""
    index = {}
    for fbs_path in SCHEMAS_SRC.rglob("*.fbs"):
        _, tables = parse_fbs(fbs_path)
        rel = fbs_path.relative_to(SCHEMAS_SRC).parent  # ex: dispersal
        for tname in tables:
            index[tname] = BUILD_OUT / rel / f"{tname}.schema.json"
    return index


def fbs_type_to_jsonschema(ftype: str, table_index: dict, current_out_dir: Path):
    """Convertit un type de champ FlatBuffers en fragment JSON Schema (avec $ref relatif si type objet)."""
    is_array = ftype.startswith("[") and ftype.endswith("]")
    inner = ftype[1:-1] if is_array else ftype

    if inner in SCALAR_MAP:
        schema = dict(SCALAR_MAP[inner])
    elif inner in table_index:
        target = table_index[inner]
        rel = _relpath(current_out_dir, target)
        schema = {"$ref": rel}
    else:
        # union ou type inconnu (ex: MutationPayload) -> laissé en description libre
        schema = {"description": f"type non résolu automatiquement : {inner}"}

    if is_array:
        return {"type": "array", "items": schema}
    return schema


def _relpath(from_dir: Path, to_file: Path) -> str:
    import os
    rel = os.path.relpath(to_file, start=from_dir)
    return rel.replace("\\", "/")


def format_markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    """Formate un tableau Markdown en pipe-table avec colonnes alignées.

    Chaque colonne est dimensionnée sur son contenu le plus large (en-tête
    compris), puis toutes les cellules sont paddées avec des espaces pour
    que les barres verticales `|` tombent à la même position sur chaque
    ligne — lisible aussi bien dans le fichier source que rendu.
    """
    # échappe les "|" internes pour ne pas casser la structure du tableau
    def esc(cell: str) -> str:
        return str(cell).replace("|", "\\|")

    escaped_headers = [esc(h) for h in headers]
    escaped_rows = [[esc(c) for c in row] for row in rows]

    columns = [escaped_headers] + escaped_rows
    widths = [
        max(len(row[i]) for row in columns)
        for i in range(len(escaped_headers))
    ]

    def fmt_row(cells: list[str]) -> str:
        padded = [cell.ljust(width) for cell, width in zip(cells, widths)]
        return "| " + " | ".join(padded) + " |"

    separator = "|-" + "-|-".join("-" * w for w in widths) + "-|"

    lines = [fmt_row(escaped_headers), separator]
    lines += [fmt_row(row) for row in escaped_rows]
    return "\n".join(lines) + "\n"


def generate():
    BUILD_OUT.mkdir(parents=True, exist_ok=True)
    table_index = build_index()
    generated = []

    for fbs_path in SCHEMAS_SRC.rglob("*.fbs"):
        namespace, tables = parse_fbs(fbs_path)
        rel_dir = fbs_path.relative_to(SCHEMAS_SRC).parent
        out_dir = BUILD_OUT / rel_dir
        out_dir.mkdir(parents=True, exist_ok=True)

        for tname, tdata in tables.items():
            properties = {}
            required = []
            for f in tdata["fields"]:
                properties[f["name"]] = fbs_type_to_jsonschema(f["type"], table_index, out_dir)
                if f["doc"]:
                    properties[f["name"]]["description"] = f["doc"]
                required.append(f["name"])

            schema = {
                "$schema": "http://json-schema.org/draft-07/schema#",
                "$id": f"{namespace}.{tname}",
                "title": tname,
                "description": tdata["doc"] or f"Table {tname} ({namespace})",
                "type": "object",
                "source_fbs": str(fbs_path.relative_to(ROOT)),
                "properties": properties,
                "required": required,
            }
            out_file = out_dir / f"{tname}.schema.json"
            out_file.write_text(json.dumps(schema, indent=2, ensure_ascii=False), encoding="utf-8")
            generated.append(out_file)

            # Fragment Markdown dérivé, inclus par snippet depuis les pages docs/02-schemas
            table_md = out_dir / f"{tname}.table.md"
            rows = [
                [f"`{f['name']}`", f"`{f['type']}`", f["doc"]]
                for f in tdata["fields"]
            ]
            table_md.write_text(
                format_markdown_table(["Champ", "Type", "Description"], rows),
                encoding="utf-8",
            )
            generated.append(table_md)

    return generated


if __name__ == "__main__":
    files = generate()
    print(f"[fbs_to_jsonschema] {len(files)} fichiers générés dans {BUILD_OUT}", file=sys.stderr)
