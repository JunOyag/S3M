#!/usr/bin/env python3
"""
run_scenario.py — Orchestrateur de scénario d'intégration.

STATUT : squelette Phase 0. Ce script suppose que `impl/node` et
`impl/connector` exposent déjà une interface minimale (health-check HTTP,
CLI, ou équivalent) — à adapter une fois cette interface fixée en Phase 2.
Le SQUELETTE DU FLUX (up -> inject -> attendre -> assert -> down -> rapport)
est en revanche stable et ne devrait pas changer.

Usage:
    python3 run_scenario.py <nom-du-scenario>
    python3 run_scenario.py --list
"""
from __future__ import annotations
import argparse
import importlib
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
COMPOSE_FILE = ROOT / "docker-compose.test.yml"
SCENARIOS_DIR = ROOT / "scenarios"


def compose(*args: str) -> None:
    subprocess.run(["docker", "compose", "-f", str(COMPOSE_FILE), *args], check=True)


def list_scenarios() -> list[str]:
    return sorted(p.stem for p in SCENARIOS_DIR.glob("*.py") if p.stem != "__init__")


def run(name: str) -> bool:
    mod = importlib.import_module(f"scenarios.{name}")
    print(f"=== Scénario : {name} ===")
    print(f"Réf. protocole : {getattr(mod, 'SPEC_REF', '(non renseignée)')}")
    print(f"Attendu        : {getattr(mod, 'EXPECTED', '(non renseigné)')}\n")

    print("[1/5] Démarrage de la stack (propre, sans état résiduel)...")
    compose("up", "-d", "--build")

    try:
        print("[2/5] Injection de la panne...")
        mod.inject()

        wait_s = getattr(mod, "WAIT_SECONDS", 30)
        print(f"[3/5] Attente {wait_s}s (délai de détection/réparation attendu)...")
        time.sleep(wait_s)

        print("[4/5] Vérification des invariants attendus...")
        ok, details = mod.assert_recovery()

        print("[5/5] Résultat :")
        for line in details:
            print(f"   {line}")
        print(f"\n=== {'PASS' if ok else 'FAIL'} : {name} ===")
        return ok
    finally:
        compose("down", "-v")  # -v : purge les volumes, pas d'état entre scénarios


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("scenario", nargs="?")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()

    if args.list or not args.scenario:
        print("Scénarios disponibles :")
        for s in list_scenarios():
            print(f"  - {s}")
        return

    sys.path.insert(0, str(ROOT))
    ok = run(args.scenario)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
