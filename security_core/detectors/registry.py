"""
Detector registry.

Usage:
    python3 -m security_core.detectors.registry
    python3 -m security_core.detectors.registry --list
    python3 -m security_core.detectors.registry --only ssh sudo port_scan
"""

from __future__ import annotations

import argparse
import importlib
import time
from collections.abc import Callable

DETECTORS: dict[str, str] = {
    "ssh": "security_core.detectors.ssh_bruteforce",
    "sudo": "security_core.detectors.sudo_bruteforce",
    "port_scan": "security_core.detectors.port_scan",
}


def _load_detector(module_path: str) -> Callable[[], list[dict]]:
    module = importlib.import_module(module_path)
    detect = getattr(module, "detect", None)
    if detect is None or not callable(detect):
        raise AttributeError(f"{module_path} does not expose detect()")
    return detect


def run_all(only: list[str] | None = None) -> dict[str, list[dict]]:
    targets = {
        name: module_path
        for name, module_path in DETECTORS.items()
        if only is None or name in only
    }

    results: dict[str, list[dict]] = {}

    for name, module_path in targets.items():
        print(f"[registry] running detector: {name}")
        started = time.time()

        try:
            detect = _load_detector(module_path)
            events = detect()
            elapsed = time.time() - started
            print(f"[registry]   {name}: {len(events)} event(s) in {elapsed:.2f}s")
            results[name] = events
        except Exception as exc:
            print(f"[registry]   {name}: ERROR - {exc}")
            results[name] = []

    return results


def _print_list() -> None:
    print("Available detectors:")
    for name, module_path in DETECTORS.items():
        print(f"  {name:<15} {module_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Security Automation Lab detector registry")
    parser.add_argument("--list", action="store_true", help="List registered detectors")
    parser.add_argument("--only", nargs="+", metavar="NAME", help="Run only selected detectors")
    args = parser.parse_args()

    if args.list:
        _print_list()
        return

    invalid = [name for name in (args.only or []) if name not in DETECTORS]
    if invalid:
        print(f"[registry] unknown detector(s): {', '.join(invalid)}")
        print(f"[registry] available: {', '.join(DETECTORS)}")
        return

    results = run_all(only=args.only)
    total = sum(len(events) for events in results.values())
    print(f"\n[registry] done - {total} total event(s) across {len(results)} detector(s)")


if __name__ == "__main__":
    main()
