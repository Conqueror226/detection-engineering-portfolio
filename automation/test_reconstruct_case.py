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
        out = pathlib.Path(tmp) / "case-output"
        command = [
            sys.executable, str(ROOT / "automation" / "reconstruct_case.py"),
            "--case-name", "ci-pipeline-case",
            "--pcap", str(ROOT / "fixtures" / "pipeline" / "privileged_unapproved_path.pcap"),
            "--windows", str(ROOT / "fixtures" / "pipeline" / "windows_events.json"),
            "--ip-map", str(ROOT / "fixtures" / "pipeline" / "ip_to_host.json"),
            "--out-dir", str(out),
        ]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            failures.append(f"runner exited {result.returncode}: {result.stderr or result.stdout}")
        required = [
            out / "manifest.json",
            out / "normalized" / "network.ndjson",
            out / "normalized" / "windows.ndjson",
            out / "results" / "pivot_edges.json",
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
            if any(len(item.get("sha256", "")) != 64 for item in manifest.get("inputs", [])):
                failures.append("input hashes missing from manifest")
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
