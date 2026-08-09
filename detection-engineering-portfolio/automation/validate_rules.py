#!/usr/bin/env python3
"""Validate every detection unit in the repository.

Checks, per detection:
  - metadata.yml has all required fields
  - referenced files (query, rule, test data) exist
  - ATT&CK technique IDs are well-formed (Txxxx or Txxxx.xxx)
  - both a true-positive and false-positive sample are present

Exits non-zero if any check fails, so it can gate a CI pipeline.
"""
from __future__ import annotations

import re
import sys

from _common import Detection, load_detections

REQUIRED_FIELDS = ["id", "name", "category", "query_language", "attack"]
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def validate(det: Detection) -> list[str]:
    """Return a list of error strings for one detection (empty == passed)."""
    errors: list[str] = []
    meta = det.metadata

    for field in REQUIRED_FIELDS:
        if not meta.get(field):
            errors.append(f"missing required field: '{field}'")

    # Referenced files must exist on disk.
    for key in ("query_file", "rule_file"):
        ref = meta.get(key)
        if ref and not (det.path / ref).exists():
            errors.append(f"{key} points to missing file: {ref}")

    # ATT&CK mappings must be present and well-formed.
    for entry in det.attack:
        tid = entry.get("technique_id", "")
        if not TECHNIQUE_RE.match(tid):
            errors.append(f"malformed technique_id: '{tid}'")

    # Validation samples: both classes required.
    validation = meta.get("validation", {}) or {}
    for kind in ("true_positive", "false_positive"):
        ref = validation.get(kind)
        if not ref:
            errors.append(f"missing validation sample: {kind}")
        elif not (det.path / ref).exists():
            errors.append(f"{kind} sample missing on disk: {ref}")

    return errors


def main() -> int:
    detections = load_detections()
    if not detections:
        print("No detections found.")
        return 1

    total_errors = 0
    for det in detections:
        errors = validate(det)
        if errors:
            total_errors += len(errors)
            print(f"[FAIL] {det.id}")
            for err in errors:
                print(f"       - {err}")
        else:
            print(f"[ OK ] {det.id}")

    print("-" * 48)
    if total_errors:
        print(f"Validation failed: {total_errors} error(s) across "
              f"{len(detections)} detection(s).")
        return 1
    print(f"All {len(detections)} detection(s) passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
