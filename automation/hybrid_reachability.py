#!/usr/bin/env python3
"""Normalize on-prem PivotEdge v1 and AWS CloudTrail into ReachabilityEdge v2.

The adapter preserves platform-native facts under ``native_context`` while
presenting a shared subject -> target reachability contract. It does not infer
cross-environment identity continuity from names, timestamps, or IP addresses.
Such a bridge is confirmed only by an explicit, evidence-referenced mapping.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import sys
from collections import Counter

from evidence_io import evidence_descriptor, load_json_records


SCHEMA_VERSION = "2.0"


def _canonical_hash(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def _utc(value: str) -> str:
    parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _entity(kind: str, identifier: str, display_name: str | None = None) -> dict:
    result = {"kind": kind, "id": identifier}
    if display_name:
        result["display_name"] = display_name
    return result


def _on_prem_identity(value: str) -> dict:
    return _entity("identity", f"identity:on_prem:{value}", value)


def _on_prem_host(value: str) -> dict:
    return _entity("host", f"host:on_prem:{value}", value)


def pivot_edge_to_reachability(edge: dict) -> dict:
    """Lift the frozen Windows-specific PivotEdge v1 into the v2 contract."""
    subject = _on_prem_identity(edge["identity"])
    effective = _on_prem_identity(edge["effective_identity"])
    refs = [
        {"source_type": source_type, "evidence_ref": str(reference)}
        for source_type, reference in (edge.get("evidence_refs") or {}).items()
        if reference
    ]
    transition = edge.get("credential_transition")
    normalized_transition = None
    if transition:
        normalized_transition = {
            "from_subject": _on_prem_identity(transition["from_identity"]),
            "to_subject": _on_prem_identity(transition["to_identity"]),
            "state": transition["state"],
            "evidence_ref": transition.get("evidence_ref"),
        }
    native = {
        key: edge[key]
        for key in ("service", "source_ip", "target_ip", "logon_id", "source_logon_id")
        if edge.get(key) is not None
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "edge_id": f"onprem:{edge['edge_id']}",
        "@timestamp": _utc(edge["@timestamp"]),
        "environment": "on_prem",
        "edge_type": "authenticated_to",
        "subject": subject,
        "effective_subject": effective,
        "source": _on_prem_host(edge["source_host"]),
        "target": _on_prem_host(edge["target_host"]),
        "session": {
            "id": edge.get("logon_id"),
            "parent_session_id": edge.get("source_logon_id"),
            "state": "confirmed" if edge.get("logon_id") else "unknown",
        },
        "auth_state": edge.get("auth_state", "unknown"),
        "privilege_state": edge.get("privilege_state", "unknown"),
        "credential_transition": normalized_transition,
        "evidence_refs": refs,
        "native_context": native,
    }


def _cloudtrail_records(path: pathlib.Path) -> list[dict]:
    expanded = []
    for record in load_json_records(path):
        records = record.get("Records") if isinstance(record, dict) else None
        if isinstance(records, list):
            expanded.extend(item for item in records if isinstance(item, dict))
            continue
        detail = record.get("detail") if isinstance(record, dict) else None
        expanded.append(detail if isinstance(detail, dict) else record)
    return expanded


def _aws_actor(record: dict) -> tuple[str | None, str | None]:
    identity = record.get("userIdentity") or {}
    actor_id = identity.get("arn") or identity.get("principalId")
    display = identity.get("userName") or actor_id
    return (str(actor_id), str(display)) if actor_id else (None, None)


def cloudtrail_assume_role_to_reachability(record: dict, *, source_file: str | None = None,
                                           source_sha256: str | None = None) -> tuple[dict | None, str | None]:
    """Materialize one successful STS AssumeRole record, or return a reason."""
    if record.get("eventSource") != "sts.amazonaws.com" or record.get("eventName") != "AssumeRole":
        return None, "not sts:AssumeRole"
    if record.get("errorCode") or record.get("errorMessage"):
        return None, "failed AssumeRole"

    event_id = record.get("eventID")
    timestamp = record.get("eventTime")
    actor_id, actor_display = _aws_actor(record)
    request = record.get("requestParameters") or {}
    response = record.get("responseElements") or {}
    assumed = response.get("assumedRoleUser") or {}
    credentials = response.get("credentials") or {}
    role_arn = request.get("roleArn")
    session_id = credentials.get("accessKeyId") or assumed.get("assumedRoleId")
    missing = [name for name, value in (
        ("eventID", event_id), ("eventTime", timestamp), ("actor", actor_id),
        ("requestParameters.roleArn", role_arn), ("assumed session id", session_id),
    ) if not value]
    if missing:
        return None, "missing " + ", ".join(missing)

    actor = _entity("cloud_principal", f"principal:aws:{actor_id}", actor_display)
    role = _entity("cloud_role", f"role:aws:{role_arn}", str(role_arn).rsplit("/", 1)[-1])
    evidence = {"source_type": "cloudtrail", "evidence_ref": str(event_id)}
    if source_file:
        evidence["source_file"] = source_file
    if source_sha256:
        evidence["source_sha256"] = source_sha256

    return {
        "schema_version": SCHEMA_VERSION,
        "edge_id": f"aws:{_canonical_hash(record)[:24]}",
        "@timestamp": _utc(str(timestamp)),
        "environment": "aws",
        "edge_type": "assumed_role",
        "subject": actor,
        "effective_subject": role,
        "source": actor,
        "target": role,
        "session": {"id": str(session_id), "parent_session_id": None, "state": "confirmed"},
        "auth_state": "confirmed",
        "privilege_state": "unknown",
        "credential_transition": {
            "from_subject": actor,
            "to_subject": role,
            "state": "confirmed",
            "evidence_ref": str(event_id),
        },
        "evidence_refs": [evidence],
        "native_context": {
            "event_source": "sts.amazonaws.com",
            "event_name": "AssumeRole",
            "aws_region": record.get("awsRegion"),
            "source_ip": record.get("sourceIPAddress"),
            "role_session_name": request.get("roleSessionName"),
            "assumed_role_arn": assumed.get("arn"),
        },
    }, None


def load_cloudtrail_sources(paths: list[pathlib.Path]) -> tuple[list[dict], dict]:
    edges = []
    reasons = Counter()
    sources = []
    for path in paths:
        descriptor = evidence_descriptor(path, "aws_cloudtrail")
        records = _cloudtrail_records(path)
        accepted = 0
        for record in records:
            edge, reason = cloudtrail_assume_role_to_reachability(
                record, source_file=path.name, source_sha256=descriptor["sha256"]
            )
            if edge is None:
                reasons[reason or "unclassified"] += 1
                continue
            edges.append(edge)
            accepted += 1
        sources.append({"file_name": path.name, "raw_records": len(records), "accepted_records": accepted})
    edges.sort(key=lambda item: (item["@timestamp"], item["edge_id"]))
    return edges, {"sources": sources, "quality_issues": dict(sorted(reasons.items()))}


def cross_environment_continuity(on_prem_identity: str, cloud_principal: str,
                                 mappings: list[dict]) -> dict:
    """Confirm a hybrid bridge only when an explicit mapping carries evidence."""
    for mapping in mappings:
        if (mapping.get("on_prem_identity") == on_prem_identity
                and mapping.get("cloud_principal") == cloud_principal
                and mapping.get("state") == "confirmed"
                and mapping.get("evidence_ref")):
            return {"state": "confirmed", "evidence_ref": mapping["evidence_ref"]}
    return {"state": "unknown", "evidence_ref": None}


def _read_array(path: pathlib.Path) -> list[dict]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"{path}: expected a JSON array of objects")
    return value


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Build platform-neutral ReachabilityEdge v2 records")
    parser.add_argument("--pivot-edges", action="append", type=pathlib.Path, default=[])
    parser.add_argument("--cloudtrail", action="append", type=pathlib.Path, default=[])
    parser.add_argument("--out", required=True, type=pathlib.Path)
    parser.add_argument("--quality-output", type=pathlib.Path)
    args = parser.parse_args(argv)
    if not (args.pivot_edges or args.cloudtrail):
        parser.error("provide --pivot-edges and/or --cloudtrail")
    for path in [*args.pivot_edges, *args.cloudtrail]:
        if not path.is_file():
            print(f"missing input: {path}", file=sys.stderr)
            return 2

    edges = []
    for path in args.pivot_edges:
        edges.extend(pivot_edge_to_reachability(item) for item in _read_array(path))
    cloud_edges, quality = load_cloudtrail_sources(args.cloudtrail)
    edges.extend(cloud_edges)
    edges.sort(key=lambda item: (item["@timestamp"], item["edge_id"]))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(edges, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.quality_output:
        args.quality_output.parent.mkdir(parents=True, exist_ok=True)
        args.quality_output.write_text(json.dumps(quality, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"reachability edges: {len(edges)} ({len(cloud_edges)} AWS)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
