#!/usr/bin/env python3
"""Generate a MITRE ATT&CK Navigator layer from detection metadata.

Output: attack_navigator/coverage_layer.json
Load it at https://mitre-attack.github.io/attack-navigator/ to view a heatmap
of the techniques this portfolio detects.
"""
from __future__ import annotations

import json
from pathlib import Path

from _common import REPO_ROOT, load_detections

OUTPUT = REPO_ROOT / "attack_navigator" / "coverage_layer.json"
COLOR = "#2E7D32"  # green for covered techniques


def main() -> int:
    detections = load_detections()
    if not detections:
        print("No detections found.")
        return 1

    # Aggregate detections per technique (a technique may have several).
    per_technique: dict[str, list[str]] = {}
    for det in detections:
        for entry in det.attack:
            tid = entry.get("technique_id")
            if tid:
                per_technique.setdefault(tid, []).append(det.name)

    techniques = [
        {
            "techniqueID": tid,
            "score": len(names),
            "color": COLOR,
            "comment": "; ".join(names),
            "enabled": True,
        }
        for tid, names in sorted(per_technique.items())
    ]

    layer = {
        "name": "Detection Portfolio Coverage",
        "versions": {"attack": "19.2", "navigator": "5.0.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Techniques covered by this detection engineering portfolio.",
        "techniques": techniques,
        "gradient": {
            "colors": ["#FFF3E0", COLOR],
            "minValue": 0,
            "maxValue": max((t["score"] for t in techniques), default=1),
        },
        "legendItems": [{"label": "Covered", "color": COLOR}],
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(layer, indent=2), encoding="utf-8")
    print(f"Wrote {len(techniques)} technique(s) to {OUTPUT.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
