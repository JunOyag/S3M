#!/usr/bin/env python3
"""
plan.py
=======
Transforme le graphe `refs` de manifest.yml (conçu pour la navigation
documentaire, donc pas garanti acyclique — deux concepts peuvent se
référencer mutuellement) en un plan d'implémentation exploitable par une
équipe d'agents : des "vagues" de clusters pouvant être développés en
parallèle, chaque vague ne démarrant qu'une fois la précédente terminée.

Algorithme :
  1. Tarjan — regroupe les id mutuellement dépendants (cycles) en
     composantes fortement connexes (SCC). Un cycle comme
     `crypto.k-block` <-> `fs.DirectoryEntry` signifie concrètement que ces
     deux mécanismes doivent être conçus/implémentés ensemble, par la même
     personne ou le même agent — jamais scindés entre deux vagues.
  2. Condensation — le graphe des SCC (chacune traitée comme un noeud
     unique) est, par construction, un DAG.
  3. Kahn — tri topologique du DAG condensé en vagues : chaque vague
     contient tous les clusters dont toutes les dépendances sont déjà
     résolues par les vagues précédentes → parallélisation maximale au
     sein d'une vague, ordre strict entre vagues.

Usage:
    python3 scripts/plan.py                     # plan complet, toutes sections
    python3 scripts/plan.py --section 04-protocols
    python3 scripts/plan.py --json impl/plan.json
    python3 scripts/plan.py --exclude overview.architecture overview.glossary secours.reference-consolidee
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from collections import defaultdict, deque

import yaml

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "manifest.yml"

# Pages purement documentaires (sommaires, glossaire, index de liens) —
# rien à implémenter, exclues du plan par défaut pour ne pas polluer les
# vagues avec des noeuds sans code associé.
DEFAULT_EXCLUDE = {"overview.architecture", "overview.glossary", "secours.reference-consolidee"}


def load_graph_from_manifest(exclude: set[str]) -> tuple[dict, dict]:
    data = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    pages = {p["id"]: p for p in data["pages"] if p["id"] not in exclude}
    graph = {pid: [r for r in p.get("refs", []) if r in pages] for pid, p in pages.items()}
    return pages, graph


def load_graph_from_schemas() -> tuple[dict, dict]:
    """Graphe des $ref RÉELS entre tables .fbs (celui qu'un compilateur verrait) —
    contrairement au graphe manifest.yml, celui-ci est structurellement
    garanti acyclique (une table ne peut pas s'auto-contenir), donc
    directement exploitable pour ordonner la génération de code."""
    import json
    build_dir = ROOT / "build" / "schemas"
    if not build_dir.exists():
        raise SystemExit("build/schemas/ absent — lancer d'abord "
                          "`python3 scripts/fbs_to_jsonschema.py`.")
    pages, graph = {}, {}
    for f in build_dir.rglob("*.schema.json"):
        d = json.loads(f.read_text(encoding="utf-8"))
        title = d["title"]
        pages[title] = {"path": d.get("source_fbs", str(f)), "title": title}
        refs = set()

        def walk(node):
            if isinstance(node, dict):
                if "$ref" in node:
                    refs.add(node["$ref"].split("/")[-1].replace(".schema.json", ""))
                for v in node.values():
                    walk(v)
            elif isinstance(node, list):
                for v in node:
                    walk(v)

        walk(d.get("properties", {}))
        graph[title] = sorted(refs)
    return pages, graph


def load_graph(source: str, exclude: set[str]) -> tuple[dict, dict]:
    if source == "schema":
        return load_graph_from_schemas()
    return load_graph_from_manifest(exclude)


def tarjan_scc(graph: dict) -> list[list[str]]:
    """Retourne les composantes fortement connexes, en ordre topologique inverse."""
    index_counter = [0]
    stack, lowlink, index, on_stack = [], {}, {}, {}
    result = []

    def strongconnect(v):
        index[v] = index_counter[0]
        lowlink[v] = index_counter[0]
        index_counter[0] += 1
        stack.append(v)
        on_stack[v] = True

        for w in graph.get(v, []):
            if w not in index:
                strongconnect(w)
                lowlink[v] = min(lowlink[v], lowlink[w])
            elif on_stack.get(w):
                lowlink[v] = min(lowlink[v], index[w])

        if lowlink[v] == index[v]:
            component = []
            while True:
                w = stack.pop()
                on_stack[w] = False
                component.append(w)
                if w == v:
                    break
            result.append(component)

    sys.setrecursionlimit(10000)
    for v in graph:
        if v not in index:
            strongconnect(v)
    return result


def condense(graph: dict, sccs: list[list[str]]) -> tuple[dict, dict]:
    """Construit le DAG des SCC (chaque SCC = un noeud condensé)."""
    owner = {node: i for i, comp in enumerate(sccs) for node in comp}
    cgraph = defaultdict(set)
    for u, deps in graph.items():
        for v in deps:
            cu, cv = owner[u], owner[v]
            if cu != cv:
                cgraph[cu].add(cv)
    return cgraph, owner


def waves_from_condensation(sccs: list[list[str]], cgraph: dict) -> list[list[int]]:
    """Tri topologique de Kahn du DAG condensé, groupé en vagues parallélisables."""
    n = len(sccs)
    indegree = {i: 0 for i in range(n)}
    for u, deps in cgraph.items():
        for v in deps:
            indegree[v] += 1  # v dépend de u -> une arête u->v signifie "u référence v", donc v doit être prêt AVANT u

    # Ici l'arête cgraph[u] = {v, ...} signifie "u référence v" (v = dépendance de u).
    # Pour l'ordre d'implémentation, v doit être traité avant u : on inverse donc
    # le sens pour le calcul des vagues (in-degree = nombre de dépendances non résolues).
    dep_count = {i: len(cgraph.get(i, set())) for i in range(n)}
    dependents = defaultdict(list)  # v -> [u, ...] qui dépendent de v
    for u, deps in cgraph.items():
        for v in deps:
            dependents[v].append(u)

    waves = []
    ready = deque(i for i in range(n) if dep_count[i] == 0)
    remaining = dict(dep_count)
    processed = set()

    while ready:
        wave = sorted(ready)
        waves.append(wave)
        ready = deque()
        for i in wave:
            processed.add(i)
        for i in wave:
            for dependent in dependents.get(i, []):
                if dependent in processed:
                    continue
                remaining[dependent] -= 1
                if remaining[dependent] == 0:
                    ready.append(dependent)

    if len(processed) != n:
        missing = set(range(n)) - processed
        raise RuntimeError(f"Cycle résiduel inattendu dans le graphe condensé : SCC {missing}")

    return waves


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--graph", choices=["manifest", "schema"], default="manifest",
                         help="source du graphe : 'manifest' (refs documentaires, contient des cycles — "
                              "cf. avertissement) ou 'schema' (le graphe réel des $ref .fbs, garanti acyclique, "
                              "pour ordonner la génération de code)")
    parser.add_argument("--section", help="ne montrer que les id/tables dont le chemin contient ce préfixe")
    parser.add_argument("--json", help="écrire aussi le plan en JSON à ce chemin")
    parser.add_argument("--exclude", nargs="*", default=list(DEFAULT_EXCLUDE), help="id à exclure (mode manifest uniquement)")
    args = parser.parse_args()

    exclude = set(args.exclude)
    pages, graph = load_graph(args.graph, exclude)

    if args.graph == "manifest":
        cycle_count = sum(1 for comp in tarjan_scc(graph) if len(comp) > 1)
        if cycle_count:
            print(f"⚠️  Graphe manifest.yml : {cycle_count} cycle(s) de renvoi documentaire détecté(s) — "
                  f"les clusters marqués [COUPLÉ] ci-dessous en découlent. Voir --graph schema pour un "
                  f"ordre de génération de code garanti acyclique.\n", file=sys.stderr)

    sccs = tarjan_scc(graph)
    cgraph, owner = condense(graph, sccs)
    waves = waves_from_condensation(sccs, cgraph)

    plan = []
    for wave_num, wave in enumerate(waves, start=1):
        clusters = []
        for scc_idx in wave:
            ids = sccs[scc_idx]
            if args.section and not any(pages[i]["path"].startswith(args.section) for i in ids):
                continue
            clusters.append({
                "cluster_size": len(ids),
                "ids": sorted(ids),
                "paths": sorted(pages[i]["path"] for i in ids),
                "coupled": len(ids) > 1,
            })
        if clusters:
            plan.append({"wave": wave_num, "clusters": clusters})

    # Ré-affichage humain
    print(f"=== Plan d'implémentation — {len(pages)} unité(s), {len(sccs)} cluster(s), {len(plan)} vague(s) ===\n")
    for w in plan:
        print(f"--- Vague {w['wave']} ({len(w['clusters'])} cluster(s), parallélisables entre eux) ---")
        for c in w["clusters"]:
            tag = " [COUPLÉ — même agent obligatoire]" if c["coupled"] else ""
            print(f"  • {', '.join(c['ids'])}{tag}")
        print()

    if args.json:
        out_path = ROOT / args.json
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(plan, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[plan] JSON écrit dans {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
