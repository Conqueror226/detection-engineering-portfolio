#!/usr/bin/env python3
"""CLI smoke test for the evidence-to-report workflow."""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parent.parent


def main() -> int:
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        outputs = []
        for run_number in (1, 2):
            out = pathlib.Path(tmp) / f"case-output-{run_number}"
            command = [
                sys.executable, str(ROOT / "automation" / "reconstruct_case.py"),
                "--case-name", "ci-pipeline-case",
                "--pcap", str(ROOT / "fixtures" / "pipeline" / "privileged_unapproved_path.pcap"),
                "--windows", str(ROOT / "fixtures" / "pipeline" / "windows_events.json"),
                "--cloudtrail", str(ROOT / "fixtures" / "hybrid" / "aws_assume_role.json"),
                "--ip-map", str(ROOT / "fixtures" / "pipeline" / "ip_to_host.json"),
                "--out-dir", str(out),
            ]
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            if result.returncode != 0:
                failures.append(f"run {run_number} exited {result.returncode}: {result.stderr or result.stdout}")
            outputs.append(out)

        out = outputs[0]
        required = [
            out / "manifest.json",
            out / "normalized" / "network.ndjson",
            out / "normalized" / "windows.ndjson",
            out / "results" / "pivot_edges.json",
            out / "results" / "reachability_edges_v2.json",
            out / "results" / "findings.json",
            out / "results" / "data_quality.json",
            out / "results" / "reconstruction_report.md",
        ]
        missing = [path.name for path in required if not path.is_file()]
        if missing:
            failures.append(f"missing outputs: {missing}")
        if (out / "manifest.json").is_file():
            manifest = json.loads((out / "manifest.json").read_text())
            if manifest["counts"].get("pivot_edges") != 2:
                failures.append(f"expected 2 edges, got {manifest['counts']}")
            if manifest["counts"].get("reachability_edges_v2") != 3:
                failures.append(f"expected 3 unified edges, got {manifest['counts']}")
            if manifest["counts"].get("aws_reachability_edges") != 1:
                failures.append(f"expected 1 AWS edge, got {manifest['counts']}")
            if any(len(item.get("sha256", "")) != 64 for item in manifest.get("inputs", [])):
                failures.append("input hashes missing from manifest")
            context_inputs = [item for item in manifest.get("inputs", []) if item.get("role") == "context"]
            if len(context_inputs) != 5:
                failures.append(f"expected five hashed context inputs, got {len(context_inputs)}")
            if len(manifest.get("derivation_id", "")) != 64:
                failures.append("stable derivation_id missing from manifest")
            if not manifest.get("code_revision"):
                failures.append("code revision missing from manifest")
            expected_timings = {
                "network_ingest_ms", "windows_ingest_ms", "cloud_ingest_ms",
                "edge_materialization_ms", "graph_classification_ms",
                "hybrid_normalization_ms", "derived_output_write_ms", "pipeline_total_ms",
            }
            performance = manifest.get("performance") or {}
            if set(performance) != expected_timings or any(value < 0 for value in performance.values()):
                failures.append(f"invalid performance instrumentation: {performance}")
        second_manifest_path = outputs[1] / "manifest.json"
        if (out / "manifest.json").is_file() and second_manifest_path.is_file():
            first_manifest = json.loads((out / "manifest.json").read_text())
            second_manifest = json.loads(second_manifest_path.read_text())
            if first_manifest.get("derivation_id") != second_manifest.get("derivation_id"):
                failures.append("same evidence + parameters did not reproduce the derivation_id")
            first_hashes = [item["sha256"] for item in first_manifest.get("outputs", [])]
            second_hashes = [item["sha256"] for item in second_manifest.get("outputs", [])]
            if first_hashes != second_hashes:
                failures.append("derived output hashes changed across identical runs")
        if (out / "results" / "findings.json").is_file():
            findings = json.loads((out / "results" / "findings.json").read_text())
            if "CRITICAL_UNAPPROVED_PATH" not in {item["label"] for item in findings}:
                failures.append(f"critical unapproved path missing: {findings}")
        if (out / "results" / "reconstruction_report.md").is_file():
            report = (out / "results" / "reconstruction_report.md").read_text()
            if "Interpretive boundary" not in report or "SHA-256" not in report:
                failures.append("report lacks provenance or interpretation boundary")

    if failures:
        print("[FAIL] reconstruct-case CLI")
        for failure in failures:
            print(f"       - {failure}")
        return 1
    print("[PASS] reconstruct-case CLI: normalized evidence, edges, findings, report, manifest")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
