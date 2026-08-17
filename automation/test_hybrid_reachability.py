#!/usr/bin/env python3
"""Contract and evidence-based tests for hybrid ReachabilityEdge v2."""
from __future__ import annotations

import json
import pathlib
import sys

from jsonschema import Draft7Validator, FormatChecker

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "automation"))

from hybrid_reachability import (  # noqa: E402
    cross_environment_continuity,
    load_cloudtrail_sources,
    pivot_edge_to_reachability,
)


def main() -> int:
    failures = []
    schema = json.loads((ROOT / "schemas" / "reachability_edge.schema.json").read_text())
    Draft7Validator.check_schema(schema)
    validator = Draft7Validator(schema, format_checker=FormatChecker())

    v1_path = (ROOT / "detections" / "T1021_privileged_pivot_progression" /
               "test_data" / "scenarios" / "03_unapproved_da_to_dc.json")
    v1 = json.loads(v1_path.read_text())[0]
    on_prem = pivot_edge_to_reachability(v1)
    if list(validator.iter_errors(on_prem)):
        failures.append("on-prem v1 adapter did not satisfy ReachabilityEdge v2")
    if on_prem["environment"] != "on_prem" or on_prem["edge_type"] != "authenticated_to":
        failures.append(f"unexpected on-prem normalization: {on_prem}")

    cloud_path = ROOT / "fixtures" / "hybrid" / "aws_assume_role.json"
    aws_edges, quality = load_cloudtrail_sources([cloud_path])
    if len(aws_edges) != 1:
        failures.append(f"expected one successful AssumeRole edge, got {len(aws_edges)}")
    else:
        aws = aws_edges[0]
        errors = list(validator.iter_errors(aws))
        if errors:
            failures.append("AWS adapter schema errors: " + "; ".join(error.message for error in errors))
        if aws["credential_transition"]["state"] != "confirmed":
            failures.append("successful AssumeRole was not represented as a confirmed transition")
        if aws["privilege_state"] != "unknown":
            failures.append("adapter inferred privilege instead of leaving policy-dependent state unknown")
        if not aws["evidence_refs"][0].get("source_sha256"):
            failures.append("CloudTrail evidence hash missing")
    if quality["sources"][0]["raw_records"] != 2 or quality["sources"][0]["accepted_records"] != 1:
        failures.append(f"unexpected CloudTrail quality stats: {quality}")

    inferred = cross_environment_continuity(
        "CORP\\alice", "arn:aws:iam::111122223333:user/alice", []
    )
    if inferred["state"] != "unknown":
        failures.append("cross-environment continuity was inferred without an explicit mapping")
    confirmed = cross_environment_continuity(
        "CORP\\alice",
        "arn:aws:iam::111122223333:user/alice",
        [{
            "on_prem_identity": "CORP\\alice",
            "cloud_principal": "arn:aws:iam::111122223333:user/alice",
            "state": "confirmed",
            "evidence_ref": "id-governance:map-001",
        }],
    )
    if confirmed != {"state": "confirmed", "evidence_ref": "id-governance:map-001"}:
        failures.append(f"explicit hybrid mapping was not honored: {confirmed}")

    if failures:
        print("[FAIL] hybrid reachability")
        for failure in failures:
            print(f"       - {failure}")
        return 1
    print("[PASS] hybrid reachability: v1 lift + CloudTrail adapter + explicit bridge requirement")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
