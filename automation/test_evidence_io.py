#!/usr/bin/env python3
"""Input-adapter tests for JSON, NDJSON, and Elasticsearch exports."""
from __future__ import annotations

import json
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from evidence_io import evidence_descriptor, load_windows_sources  # noqa: E402


def base_event(code, data, record_id):
    return {
        "@timestamp": "2026-08-10T10:00:30+00:00",
        "event": {"code": code},
        "host": {"name": "srv-app-01.corp.example"},
        "winlog": {"record_id": record_id, "event_data": data},
    }


def main() -> int:
    failures = []
    ip_map = {"10.0.0.60": "SRV-APP-01"}
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        logon = base_event(4624, {
            "TargetUserName": "bob", "TargetDomainName": "CORP",
            "TargetLogonId": "0x111", "IpAddress": "::ffff:10.0.0.10", "LogonType": "10",
        }, 100)
        priv = base_event("4672", {
            "SubjectUserName": "bob", "SubjectDomainName": "CORP", "SubjectLogonId": "0x111",
        }, 101)
        cred = base_event("4648", {
            "SubjectUserName": "bob", "SubjectLogonId": "0x111",
            "TargetUserName": "dom_admin", "TargetServerName": "dc01.corp.example",
        }, 102)

        array_path = root / "array.json"
        array_path.write_text(json.dumps([logon]), encoding="utf-8")
        search_path = root / "search.json"
        search_path.write_text(json.dumps({"hits": {"hits": [{"_id": "elastic-1", "_source": priv}]}}), encoding="utf-8")
        ndjson_path = root / "bulk.ndjson"
        ndjson_path.write_text(
            json.dumps({"index": {"_index": "logs-windows"}}) + "\n" + json.dumps(cred) + "\n",
            encoding="utf-8",
        )

        events, stats = load_windows_sources([array_path, search_path, ndjson_path], ip_map)
        if len(events) != 3:
            failures.append(f"expected 3 normalized events, got {len(events)}")
        if stats["by_event_code"] != {"4624": 1, "4648": 1, "4672": 1}:
            failures.append(f"event distribution wrong: {stats['by_event_code']}")
        logons = [event for event in events if event["event"]["code"] == "4624"]
        if not logons or logons[0]["host"].get("ip") != "10.0.0.60":
            failures.append(f"host-map enrichment failed: {logons}")
        if logons and logons[0]["host"].get("name") != "SRV-APP-01":
            failures.append(f"canonical host naming failed: {logons[0]['host']}")
        if logons and logons[0]["winlog"]["event_data"].get("IpAddress") != "10.0.0.10":
            failures.append("IPv4-mapped IPv6 source was not canonicalized")
        if stats["quality_issues"]:
            failures.append(f"unexpected quality issues: {stats['quality_issues']}")
        desc = evidence_descriptor(array_path, "windows_events")
        if len(desc["sha256"]) != 64 or desc["size_bytes"] <= 0:
            failures.append(f"invalid evidence descriptor: {desc}")

    if failures:
        print("[FAIL] evidence input adapters")
        for failure in failures:
            print(f"       - {failure}")
        return 1
    print("[PASS] evidence input adapters: JSON, NDJSON, Elasticsearch, host enrichment, hashing")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
