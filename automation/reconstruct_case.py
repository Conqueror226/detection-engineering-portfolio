#!/usr/bin/env python3
"""Run an offline reconstruction over real PCAP, Windows, and AWS evidence.

The runner preserves the v10 Windows evidence rules. It adds input adapters,
hybrid v2 normalization, provenance, quality diagnostics, contract validation,
latency instrumentation, and reviewer-readable outputs.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import json
import os
import pathlib
import subprocess
import sys
import time

from jsonschema import Draft7Validator, FormatChecker
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "automation"))
sys.path.insert(0, str(ROOT / "sensor"))

import sensor as sensor_mod  # noqa: E402
from build_reachability_graph import ReachabilityGraph  # noqa: E402
from classify_pivot_progression import classify, load_context  # noqa: E402
from evidence_io import evidence_descriptor, load_windows_sources  # noqa: E402
from hybrid_reachability import load_cloudtrail_sources, pivot_edge_to_reachability  # noqa: E402
from materialize_pivot_edges import materialize  # noqa: E402


VERSION = "post-v10-hybrid-evidence-2"
CONTEXT_FILES = (
    "asset_tiers.yml",
    "identity_roles.yml",
    "expected_admin_paths.yml",
    "approved_changes.yml",
    "known_reachability.yml",
)


def _json(path: pathlib.Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: pathlib.Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_ndjson(path: pathlib.Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")


def _code_revision() -> str:
    for name in ("DETECTION_PORTFOLIO_COMMIT", "GITHUB_SHA"):
        if os.environ.get(name):
            return os.environ[name]
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
            text=True, check=True,
        )
        return result.stdout.strip() or "unversioned"
    except (FileNotFoundError, subprocess.CalledProcessError):
        return "unversioned"


def _stable_descriptor(item: dict) -> dict:
    return {key: item[key] for key in ("role", "file_name", "sha256")}


def _derivation_id(code_revision: str, inputs: list[dict], config: dict,
                   outputs: list[dict]) -> str:
    stable = {
        "tool_version": VERSION,
        "code_revision": code_revision,
        "inputs": [_stable_descriptor(item) for item in inputs],
        "configuration": config,
        "outputs": [_stable_descriptor(item) for item in outputs],
    }
    encoded = json.dumps(stable, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _shift_timestamp(event: dict, seconds: float) -> None:
    if not seconds:
        return
    value = event.get("@timestamp")
    if not value:
        return
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    event["@timestamp"] = (parsed + dt.timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def load_network_sources(paths: list[pathlib.Path], observer: str, offset_seconds: float) -> tuple[list[dict], list[dict]]:
    events = []
    stats = []
    for path in paths:
        buffer = io.StringIO()
        with sensor_mod.PcapReader(str(path)) as packets:
            count = sensor_mod.run(packets, observer, buffer)
        descriptor = evidence_descriptor(path, "network_capture")
        for line in buffer.getvalue().splitlines():
            if not line.strip():
                continue
            event = json.loads(line)
            _shift_timestamp(event, offset_seconds)
            event["evidence"] = {
                "source_file": path.name,
                "source_sha256": descriptor["sha256"],
            }
            events.append(event)
        stats.append({"file_name": path.name, "emitted_flows": count})
    events.sort(key=lambda item: item.get("@timestamp") or "")
    return events, stats


def validate_outputs(edges: list[dict], findings: list[dict],
                     reachability_edges: list[dict]) -> list[str]:
    edge_schema = _json(ROOT / "schemas" / "pivot_edge.schema.json")
    finding_schema = _json(ROOT / "schemas" / "progression_finding.schema.json")
    reachability_schema = _json(ROOT / "schemas" / "reachability_edge.schema.json")
    edge_validator = Draft7Validator(edge_schema, format_checker=FormatChecker())
    finding_validator = Draft7Validator(finding_schema, format_checker=FormatChecker())
    reachability_validator = Draft7Validator(reachability_schema, format_checker=FormatChecker())
    errors = []
    for index, edge in enumerate(edges):
        for error in edge_validator.iter_errors(edge):
            errors.append(f"edge[{index}]: {error.message}")
    for index, finding in enumerate(findings):
        for error in finding_validator.iter_errors(finding):
            errors.append(f"finding[{index}]: {error.message}")
    for index, edge in enumerate(reachability_edges):
        for error in reachability_validator.iter_errors(edge):
            errors.append(f"reachability_edge[{index}]: {error.message}")
    return errors


def _escape(value) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def build_report(case_name: str, manifest_inputs: list[dict], network_stats: list[dict],
                 windows_stats: dict, edges: list[dict], findings: list[dict],
                 reachability_edges: list[dict], cloud_stats: dict,
                 validation_errors: list[str], config: dict) -> str:
    lines = [
        f"# Reconstruction report — {case_name}",
        "",
        f"Generated in UTC by `{VERSION}`. This report records evidence-supported joins; it does not infer continuity when required artifacts are absent.",
        "",
        "## Input evidence and provenance",
        "",
        "| Role | File | Bytes | SHA-256 |",
        "|---|---|---:|---|",
    ]
    for item in manifest_inputs:
        lines.append(f"| {_escape(item['role'])} | {_escape(item['file_name'])} | {item['size_bytes']} | `{item['sha256']}` |")
    lines += [
        "",
        "## Data-quality summary",
        "",
        f"- Network flows emitted: **{sum(item['emitted_flows'] for item in network_stats)}**",
        f"- Recognized Windows events: **{windows_stats['recognized_windows_events']}**",
        f"- Event distribution: `{json.dumps(windows_stats['by_event_code'], sort_keys=True)}`",
        f"- Materialized pivot edges: **{len(edges)}**",
        f"- Unified reachability edges: **{len(reachability_edges)}**",
        f"- AWS AssumeRole edges: **{sum(item['accepted_records'] for item in cloud_stats['sources'])}**",
        f"- Progression findings: **{len(findings)}**",
        f"- Network/logon join window: **{config['network_window_seconds']} seconds**",
        f"- Applied network time offset: **{config['network_time_offset_seconds']} seconds**",
    ]
    if windows_stats["quality_issues"]:
        lines += ["", "### Unresolved quality issues", ""]
        for issue, count in windows_stats["quality_issues"].items():
            lines.append(f"- {count} × {_escape(issue)}")
    else:
        lines += ["", "No required-field omissions were observed in the recognized Windows records."]

    lines += ["", "## Evidence-supported pivot edges", ""]
    if edges:
        lines += [
            "| Time (UTC) | Source | Target | Identity | Service | Privilege | Evidence |",
            "|---|---|---|---|---|---|---|",
        ]
        for edge in edges:
            refs = edge.get("evidence_refs") or {}
            evidence = ", ".join(f"{key}:{value}" for key, value in refs.items() if value)
            lines.append(
                f"| {_escape(edge['@timestamp'])} | {_escape(edge['source_host'])} | "
                f"{_escape(edge['target_host'])} | {_escape(edge['effective_identity'])} | "
                f"{_escape(edge['service'])} | {_escape(edge['privilege_state'])} | {_escape(evidence)} |"
            )
    else:
        lines.append("No pivot edge satisfied the configured network/authentication joins.")

    lines += ["", "## Findings", ""]
    if findings:
        lines += ["| Label | Confidence | Identity | Path | Rationale |", "|---|---|---|---|---|"]
        for finding in findings:
            lines.append(
                f"| {_escape(finding['label'])} | {_escape(finding['confidence'])} | "
                f"{_escape(finding['identity'])} | {_escape(' → '.join(finding['path']))} | "
                f"{_escape(finding['rationale'])} |"
            )
    else:
        lines.append("No finding was produced.")

    lines += ["", "## Contract validation", ""]
    if validation_errors:
        lines.append("Output contract errors were detected:")
        lines.extend(f"- {_escape(error)}" for error in validation_errors)
    else:
        lines.append("All emitted edges and findings conform to the frozen JSON contracts.")
    lines += [
        "",
        "## Interpretive boundary",
        "",
        "- A materialized edge means the configured flow, authentication, host/IP, service/logon-type, and time joins were satisfied.",
        "- Absence of an edge is not proof that movement did not occur; collection gaps, clock skew, unsupported services, NAT, or incomplete host mapping can prevent a join.",
        "- Route authorization depends on active, explicitly scoped organizational policy; incomplete scope yields insufficient context, not prohibition.",
        "- Cross-environment identity continuity requires an explicit, evidence-referenced mapping; name, time, or IP similarity is not enough.",
        "- Native EVTX does not contain the local host IP; any host-IP enrichment comes only from the examiner-provided map and is recorded as an input.",
        "",
    ]
    return "\n".join(lines)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Offline real-evidence reconstruction")
    parser.add_argument("--case-name", required=True)
    parser.add_argument("--pcap", action="append", required=True, type=pathlib.Path,
                        help="PCAP/PCAPNG file; repeat for multiple captures")
    parser.add_argument("--windows", action="append", required=True, type=pathlib.Path,
                        help="EVTX, JSON, NDJSON, or Elasticsearch _search export; repeatable")
    parser.add_argument("--cloudtrail", action="append", default=[], type=pathlib.Path,
                        help="CloudTrail JSON/NDJSON/Elasticsearch export; repeatable")
    parser.add_argument("--ip-map", required=True, type=pathlib.Path,
                        help="JSON object mapping IP address to canonical host name")
    parser.add_argument("--context-dir", type=pathlib.Path, default=ROOT / "automation" / "context")
    parser.add_argument("--out-dir", required=True, type=pathlib.Path)
    parser.add_argument("--observer-hostname", default="case-sensor")
    parser.add_argument("--network-window-seconds", type=int, default=120)
    parser.add_argument("--privilege-window-seconds", type=int, default=60)
    parser.add_argument("--transition-window-seconds", type=int, default=300)
    parser.add_argument("--progression-window-minutes", type=int, default=30)
    parser.add_argument("--network-time-offset-seconds", type=float, default=0.0,
                        help="Explicitly recorded correction applied to PCAP timestamps")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    pipeline_started = time.perf_counter()
    args = parse_args(argv)
    for path in [*args.pcap, *args.windows, *args.cloudtrail, args.ip_map]:
        if not path.is_file():
            print(f"missing input: {path}", file=sys.stderr)
            return 2
    if not args.context_dir.is_dir():
        print(f"missing context directory: {args.context_dir}", file=sys.stderr)
        return 2

    stage_started = time.perf_counter()
    raw_map = _json(args.ip_map)
    ip_map = {str(key): str(value) for key, value in raw_map.items()}
    network_events, network_stats = load_network_sources(
        args.pcap, args.observer_hostname, args.network_time_offset_seconds
    )
    network_ingest_ms = (time.perf_counter() - stage_started) * 1000

    stage_started = time.perf_counter()
    windows_events, windows_stats = load_windows_sources(args.windows, ip_map)
    windows_ingest_ms = (time.perf_counter() - stage_started) * 1000

    stage_started = time.perf_counter()
    cloud_edges, cloud_stats = load_cloudtrail_sources(args.cloudtrail)
    cloud_ingest_ms = (time.perf_counter() - stage_started) * 1000

    stage_started = time.perf_counter()
    edges = materialize(
        network_events + windows_events,
        ip_map,
        network_window_s=args.network_window_seconds,
        priv_window_s=args.privilege_window_seconds,
        transition_window_s=args.transition_window_seconds,
    )
    edge_materialization_ms = (time.perf_counter() - stage_started) * 1000

    stage_started = time.perf_counter()
    graph = ReachabilityGraph.from_records(edges)
    findings = classify(
        graph, load_context(args.context_dir), window_minutes=args.progression_window_minutes
    )
    graph_classification_ms = (time.perf_counter() - stage_started) * 1000

    stage_started = time.perf_counter()
    reachability_edges = [pivot_edge_to_reachability(edge) for edge in edges]
    reachability_edges.extend(cloud_edges)
    reachability_edges.sort(key=lambda item: (item["@timestamp"], item["edge_id"]))
    validation_errors = validate_outputs(edges, findings, reachability_edges)
    hybrid_normalization_ms = (time.perf_counter() - stage_started) * 1000

    stage_started = time.perf_counter()
    out = args.out_dir
    _write_ndjson(out / "normalized" / "network.ndjson", network_events)
    _write_ndjson(out / "normalized" / "windows.ndjson", windows_events)
    _write_json(out / "results" / "pivot_edges.json", edges)
    _write_json(out / "results" / "reachability_edges_v2.json", reachability_edges)
    _write_json(out / "results" / "findings.json", findings)
    _write_json(out / "results" / "data_quality.json", {
        "network_sources": network_stats,
        "windows": windows_stats,
        "cloudtrail": cloud_stats,
        "contract_errors": validation_errors,
    })

    inputs = [evidence_descriptor(path, "network_capture") for path in args.pcap]
    inputs += [evidence_descriptor(path, "windows_events") for path in args.windows]
    inputs += [evidence_descriptor(path, "aws_cloudtrail") for path in args.cloudtrail]
    inputs.append(evidence_descriptor(args.ip_map, "host_mapping"))
    inputs += [evidence_descriptor(args.context_dir / name, "context") for name in CONTEXT_FILES]
    config = {
        "network_window_seconds": args.network_window_seconds,
        "privilege_window_seconds": args.privilege_window_seconds,
        "transition_window_seconds": args.transition_window_seconds,
        "progression_window_minutes": args.progression_window_minutes,
        "network_time_offset_seconds": args.network_time_offset_seconds,
        "observer_hostname": args.observer_hostname,
    }
    report = build_report(
        args.case_name, inputs, network_stats, windows_stats, edges, findings,
        reachability_edges, cloud_stats, validation_errors, config,
    )
    report_path = out / "results" / "reconstruction_report.md"
    report_path.write_text(report, encoding="utf-8")

    output_paths = [
        out / "normalized" / "network.ndjson",
        out / "normalized" / "windows.ndjson",
        out / "results" / "pivot_edges.json",
        out / "results" / "reachability_edges_v2.json",
        out / "results" / "findings.json",
        out / "results" / "data_quality.json",
        report_path,
    ]
    outputs = [evidence_descriptor(path, "derived_output") for path in output_paths]
    output_write_ms = (time.perf_counter() - stage_started) * 1000
    performance = {
        "network_ingest_ms": round(network_ingest_ms, 3),
        "windows_ingest_ms": round(windows_ingest_ms, 3),
        "cloud_ingest_ms": round(cloud_ingest_ms, 3),
        "edge_materialization_ms": round(edge_materialization_ms, 3),
        "graph_classification_ms": round(graph_classification_ms, 3),
        "hybrid_normalization_ms": round(hybrid_normalization_ms, 3),
        "derived_output_write_ms": round(output_write_ms, 3),
        "pipeline_total_ms": round((time.perf_counter() - pipeline_started) * 1000, 3),
    }
    code_revision = _code_revision()
    manifest = {
        "schema_version": 2,
        "case_name": args.case_name,
        "generated_at_utc": dt.datetime.now(tz=dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "tool_version": VERSION,
        "code_revision": code_revision,
        "inputs": inputs,
        "configuration": config,
        "counts": {
            "network_events": len(network_events),
            "windows_events": len(windows_events),
            "pivot_edges": len(edges),
            "reachability_edges_v2": len(reachability_edges),
            "aws_reachability_edges": len(cloud_edges),
            "findings": len(findings),
        },
        "outputs": outputs,
        "performance": performance,
        "derivation_id": _derivation_id(code_revision, inputs, config, outputs),
    }
    _write_json(out / "manifest.json", manifest)

    print(f"case: {args.case_name}")
    print(f"network events: {len(network_events)}")
    print(f"windows events: {len(windows_events)}")
    print(f"pivot edges: {len(edges)}")
    print(f"reachability edges v2: {len(reachability_edges)} ({len(cloud_edges)} AWS)")
    print(f"findings: {len(findings)}")
    print(f"derivation id: {manifest['derivation_id']}")
    print(f"pipeline runtime: {performance['pipeline_total_ms']} ms")
    print(f"report: {report_path}")
    if validation_errors:
        print(f"contract errors: {len(validation_errors)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
