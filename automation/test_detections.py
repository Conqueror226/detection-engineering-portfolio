#!/usr/bin/env python3
"""Execute detection logic against sample data and assert expected behaviour.

For every detection whose query_language is `eql`, this:
  - parses the .eql query with Elastic's `eql` engine,
  - streams the true-positive sample and asserts at least one match,
  - streams the false-positive sample and asserts zero matches.

Sequence rules are timed correctly: event timestamps are converted to the
engine's 100-ns tick unit so `maxspan` is genuinely enforced.

Detections in other languages (e.g. `esql`) have no offline engine and are
reported as SKIPPED — they are covered by structure validation only.

Exits non-zero if any EQL logic test fails, so it can gate CI.
"""
from __future__ import annotations

import datetime
import json
import sys

import eql

from _common import Detection, load_detections

TICKS_PER_SEC = 10_000_000  # eql PythonEngine default time_unit (100-ns ticks)


def _epoch_ticks(ts: str | None) -> int:
    """Convert an ISO-8601 timestamp to engine ticks; 0 if absent."""
    if not ts:
        return 0
    dt = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    return int(dt.timestamp() * TICKS_PER_SEC)


def _to_event(doc: dict) -> "eql.Event":
    """Build an eql.Event, deriving type from event.category and time from @timestamp.

    ECS models event.category as an array; a few detections use a plain string.
    Handle both: a list takes its first element.
    """
    category = (doc.get("event", {}) or {}).get("category", "generic")
    if isinstance(category, list):
        category = category[0] if category else "generic"
    return eql.Event(category, _epoch_ticks(doc.get("@timestamp")), doc)


def _run(parsed, docs: list[dict]) -> int:
    """Return the number of matches the parsed query produces over docs."""
    engine = eql.PythonEngine()
    engine.add_query(parsed)
    hits: list = []
    engine.add_output_hook(hits.append)
    engine.stream_events([_to_event(d) for d in docs])
    engine.finalize()
    return len(hits)


def _load_samples(det: Detection) -> tuple[list[dict], list[dict]]:
    validation = det.metadata.get("validation", {}) or {}
    tp = json.loads((det.path / validation["true_positive"]).read_text(encoding="utf-8"))
    fp = json.loads((det.path / validation["false_positive"]).read_text(encoding="utf-8"))
    return tp, fp


def test_eql(det: Detection) -> list[str]:
    """Return a list of failure strings for one EQL detection (empty == passed)."""
    failures: list[str] = []
    query_text = (det.path / det.metadata["query_file"]).read_text(encoding="utf-8")
    try:
        parsed = eql.parse_query(query_text, implied_any=True, implied_base=True)
    except Exception as exc:  # noqa: BLE001 - surface any parse error as a failure
        return [f"query failed to parse: {type(exc).__name__}: {exc}"]

    tp, fp = _load_samples(det)
    tp_hits = _run(parsed, tp)
    fp_hits = _run(parsed, fp)

    if tp_hits < 1:
        failures.append(f"true-positive did not fire (expected >=1 match, got {tp_hits})")
    if fp_hits != 0:
        failures.append(f"false-positive fired (expected 0 matches, got {fp_hits})")
    return failures


def main() -> int:
    detections = load_detections()
    if not detections:
        print("No detections found.")
        return 1

    total_failures = 0
    tested = skipped = 0
    for det in detections:
        lang = (det.metadata.get("query_language") or "").lower()
        if lang == "eql":
            failures = test_eql(det)
            tested += 1
            if failures:
                total_failures += len(failures)
                print(f"[FAIL] {det.id}")
                for f in failures:
                    print(f"       - {f}")
            else:
                print(f"[PASS] {det.id}  (TP fires, FP silent)")
        else:
            skipped += 1
            print(f"[SKIP] {det.id}  ({lang or 'unknown'}: no offline engine, structure-validated only)")

    print("-" * 56)
    if total_failures:
        print(f"Logic tests FAILED: {total_failures} failure(s). "
              f"Tested {tested} EQL, skipped {skipped}.")
        return 1
    print(f"Logic tests passed. Tested {tested} EQL detection(s), skipped {skipped}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
