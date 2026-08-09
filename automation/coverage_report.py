#!/usr/bin/env python3
"""Print an ATT&CK coverage summary built from all detection metadata."""
from __future__ import annotations

from collections import defaultdict

from _common import load_detections


def main() -> int:
    detections = load_detections()
    if not detections:
        print("No detections found.")
        return 1

    # tactic -> list of (technique_id, technique_name, detection_name)
    by_tactic: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    for det in detections:
        for entry in det.attack:
            tactic = entry.get("tactic", "Unknown")
            by_tactic[tactic].append((
                entry.get("technique_id", "?"),
                entry.get("technique", "?"),
                det.name,
            ))

    techniques = {tid for rows in by_tactic.values() for tid, _, _ in rows}

    print("ATT&CK Coverage Report")
    print("=" * 60)
    for tactic in sorted(by_tactic):
        print(f"\n{tactic}")
        for tid, tname, dname in sorted(by_tactic[tactic]):
            print(f"  {tid:<12} {tname}")
            print(f"  {'':<12} -> {dname}")

    print("\n" + "=" * 60)
    print(f"Detections: {len(detections)} | "
          f"Tactics: {len(by_tactic)} | "
          f"Unique techniques: {len(techniques)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
