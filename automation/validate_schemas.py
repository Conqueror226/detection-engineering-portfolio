#!/usr/bin/env python3
"""Validate edge fixtures and classifier findings against the frozen contracts.

Structural (jsonschema + format checks) AND semantic:
  - edge_id unique within a file;
  - no confirmed transition  => effective_identity == identity;
  - confirmed transition      => to_identity == effective_identity and evidence_ref present;
  - auth_state confirmed      => evidence_refs.logon present.
Also runs the classifier over every scenario and validates each finding against
progression_finding.schema.json.
"""
from __future__ import annotations

import json
import pathlib
import sys

try:
    import jsonschema
    from jsonschema import Draft7Validator, FormatChecker
except ImportError:  # pragma: no cover
    print("jsonschema not installed"); sys.exit(1)

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCHEMAS = ROOT / "schemas"
SCENARIOS = ROOT / "detections" / "T1021_privileged_pivot_progression" / "test_data" / "scenarios"
sys.path.insert(0, str(ROOT / "automation"))


def _confirmed(ct):
    return bool(ct and ct.get("state") == "confirmed")


def semantic_errors(edges, fname):
    errs = []
    seen = set()
    for i, e in enumerate(edges):
        eid = e.get("edge_id")
        if eid in seen:
            errs.append(f"{fname}[{i}]: duplicate edge_id {eid!r}")
        seen.add(eid)
        ct = e.get("credential_transition")
        if not _confirmed(ct):
            if e.get("effective_identity") != e.get("identity"):
                errs.append(f"{fname}[{i}]: effective_identity != identity without a confirmed transition")
        else:
            if ct.get("to_identity") != e.get("effective_identity"):
                errs.append(f"{fname}[{i}]: confirmed transition to_identity != effective_identity")
            if not ct.get("evidence_ref"):
                errs.append(f"{fname}[{i}]: confirmed transition missing evidence_ref")
            if not e.get("source_logon_id"):
                errs.append(f"{fname}[{i}]: confirmed transition but no source_logon_id (lineage required)")
        refs = e.get("evidence_refs") or {}
        if e.get("auth_state") == "confirmed" and not (refs.get("logon") and refs.get("network")):
            errs.append(f"{fname}[{i}]: auth_state confirmed requires evidence_refs.network and .logon")
        if e.get("privilege_state") == "confirmed" and not refs.get("privilege"):
            errs.append(f"{fname}[{i}]: privilege_state confirmed requires evidence_refs.privilege")
    return errs


def main() -> int:
    edge_schema = json.loads((SCHEMAS / "pivot_edge.schema.json").read_text())
    finding_schema = json.loads((SCHEMAS / "progression_finding.schema.json").read_text())
    reachability_schema = json.loads((SCHEMAS / "reachability_edge.schema.json").read_text())
    for name, s in (("pivot_edge", edge_schema), ("progression_finding", finding_schema),
                    ("reachability_edge", reachability_schema)):
        Draft7Validator.check_schema(s)

    edge_v = Draft7Validator(edge_schema, format_checker=FormatChecker())
    find_v = Draft7Validator(finding_schema, format_checker=FormatChecker())
    errors: list[str] = []

    PROGRESSION = {"PIVOT_PROGRESSION","PRIVILEGED_PROGRESSION","PRIVILEGED_DESTINATION_REACH",
                   "CREDENTIAL_TRANSITION_PROGRESSION","CRITICAL_UNAPPROVED_PATH"}
    def finding_shape_errors(fnd, fname):
        e=[]
        if fnd["label"] in PROGRESSION and not (len(fnd["path"])==3 and len(fnd["edges"])==2):
            e.append(f"{fname}: {fnd['label']} must have a 3-host path and 2 edges, got path={fnd['path']} edges={fnd['edges']}")
        if fnd["label"] in {"NONE"} and len(fnd["edges"])!=1:
            e.append(f"{fname}: NONE must reference exactly 1 edge")
        return e
    from build_reachability_graph import ReachabilityGraph
    from classify_pivot_progression import classify, load_context
    ctx = load_context()

    files = sorted(SCENARIOS.glob("*.json"))
    if not files:
        errors.append("no scenario fixtures found")
    for f in files:
        edges = json.loads(f.read_text())
        for i, e in enumerate(edges):
            for err in edge_v.iter_errors(e):
                errors.append(f"{f.name}[{i}] edge: {err.message}")
        errors += semantic_errors(edges, f.name)
        # findings must conform to the output contract
        try:
            for fnd in classify(ReachabilityGraph.from_records(edges), ctx):
                for err in find_v.iter_errors(fnd):
                    errors.append(f"{f.name} finding: {err.message}")
                errors += finding_shape_errors(fnd, f.name)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{f.name}: classify raised {type(exc).__name__}: {exc}")

    if errors:
        print(f"[FAIL] schema/semantic validation ({len(errors)})")
        for e in errors[:40]:
            print(f"       - {e}")
        return 1
    print(f"[ OK ] {len(files)} scenario file(s): edges + semantics + findings all conform")
    return 0


if __name__ == "__main__":
    sys.exit(main())
