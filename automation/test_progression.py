#!/usr/bin/env python3
"""Execute the progression classifier against scenarios with EXACT assertions.

Each scenario declares the complete expected finding set — label, path, and
confidence for every finding, plus the exact count. This catches contradictory
or extra findings, not just presence of the desired label.
"""
from __future__ import annotations

import json
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
AUTOMATION = REPO_ROOT / "automation"
SCENARIOS = REPO_ROOT / "detections" / "T1021_privileged_pivot_progression" / "test_data" / "scenarios"

sys.path.insert(0, str(AUTOMATION))
from build_reachability_graph import ReachabilityGraph  # noqa: E402
from classify_pivot_progression import classify, load_context  # noqa: E402

# Exact expected findings: set of (label, path-tuple, confidence).
EXPECTED = {
    "01_no_onward_movement.json": [
        ("NONE", ("WS-ENG-12", "SRV-APP-01"), "none")],
    "02_approved_paw_to_dc.json": [
        ("EXPECTED", ("WS-ENG-12", "JUMP-PAW01", "DC01"), "none")],
    "03_unapproved_da_to_dc.json": [
        ("CRITICAL_UNAPPROVED_PATH", ("WS-ENG-12", "SRV-APP-01", "DC01"), "highest")],
    "04_non_priv_pivot.json": [
        ("PIVOT_PROGRESSION", ("WS-ENG-12", "WS-FIN-07", "SRV-APP-01"), "low")],
    "05_credential_transition.json": [
        ("CREDENTIAL_TRANSITION_PROGRESSION", ("WS-ENG-12", "SRV-APP-01", "SRV-FILE-02"), "high")],
    "06_network_without_auth.json": [
        ("INSUFFICIENT_EVIDENCE", ("WS-ENG-12", "SRV-APP-01", "SRV-FILE-02"), "low")],
    "07_justified_change.json": [
        ("JUSTIFIED", ("WS-ENG-12", "SRV-APP-01", "SRV-FILE-02"), "none")],
    "08_expired_approval.json": [
        ("PIVOT_PROGRESSION", ("WS-ENG-12", "WS-FIN-07", "SRV-APP-01"), "low")],
    "09_different_identity_second_hop.json": [
        ("NONE", ("WS-ENG-12", "SRV-APP-01"), "none"),
        ("NONE", ("SRV-APP-01", "SRV-FILE-02"), "none")],
    "10_outside_window.json": [
        ("NONE", ("WS-ENG-12", "SRV-APP-01"), "none"),
        ("NONE", ("SRV-APP-01", "DC01"), "none")],
    "11_missing_context.json": [
        ("INSUFFICIENT_CONTEXT", ("WS-ENG-12", "SRV-APP-01", "UNKNOWN-HOST"), "low")],
    # --- adversarial (step-1) ---
    "12_unknown_transition.json": [
        ("INSUFFICIENT_EVIDENCE", ("WS-ENG-12", "SRV-APP-01", "SRV-FILE-02"), "low")],
    "13_source_privileged_pivot.json": [
        ("POSSIBLE_PRIVILEGED_PROGRESSION", ("WS-ENG-12", "WS-FIN-07", "SRV-APP-01"), "low")],
    "14_unknown_intermediate.json": [
        ("INSUFFICIENT_CONTEXT", ("WS-ENG-12", "UNKNOWN-VIA", "SRV-FILE-02"), "low")],
    "15_unauth_standalone.json": [
        ("INSUFFICIENT_EVIDENCE", ("WS-ENG-12", "SRV-APP-01"), "low")],
    # repeated same-identity expansion collapses into ONE finding (occurrence_count)
    "16_distinct_repeated_edges.json": [
        ("PIVOT_PROGRESSION", ("WS-ENG-12", "WS-FIN-07", "SRV-APP-01"), "low")],
    # distinct identities over the same path -> both retained
    "17_distinct_identities.json": [
        ("PIVOT_PROGRESSION", ("WS-ENG-12", "WS-FIN-07", "SRV-APP-01"), "low"),
        ("PIVOT_PROGRESSION", ("WS-ENG-12", "WS-FIN-07", "SRV-APP-01"), "low")],
    "18_destination_privileged.json": [
        ("PRIVILEGED_DESTINATION_REACH", ("WS-ENG-12", "WS-FIN-07", "SRV-APP-01"), "medium")],
    "19_approval_before_start.json": [
        ("POSSIBLE_PRIVILEGED_PROGRESSION", ("WS-ENG-12", "SRV-APP-01", "SRV-FILE-02"), "low")],
    "20_incomplete_route_policy.json": [
        ("INSUFFICIENT_CONTEXT", ("WS-ENG-12", "SRV-APP-01", "DC01"), "low")],
}


def main() -> int:
    ctx = load_context()
    failures: list[str] = []
    for fname, expected in EXPECTED.items():
        records = json.loads((SCENARIOS / fname).read_text(encoding="utf-8"))
        findings = classify(ReachabilityGraph.from_records(records), ctx)
        got = sorted((f["label"], tuple(f["path"]), f["confidence"]) for f in findings)
        exp = sorted(expected)
        if got == exp:
            print(f"[PASS] {fname:<40} {[e[0] for e in exp]}")
        else:
            failures.append(f"{fname}\n     expected {exp}\n     got      {got}")
            print(f"[FAIL] {fname}")
            print(f"       expected {exp}")
            print(f"       got      {got}")

    print("-" * 64)
    if failures:
        print(f"Progression tests FAILED ({len(failures)}).")
        return 1
    print(f"Progression tests passed: {len(EXPECTED)} scenarios, exact match.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
