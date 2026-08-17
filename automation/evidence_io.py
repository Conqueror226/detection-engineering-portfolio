#!/usr/bin/env python3
"""Load and normalize real Windows evidence without weakening edge joins.

Supported inputs:
  * ECS/Winlogbeat JSON arrays
  * NDJSON/JSONL exports
  * Elasticsearch ``_search`` responses (``hits.hits[*]._source``)
  * Native Windows Security EVTX files (4624, 4672, and 4648)

The adapter changes representation, not meaning. Missing fields remain missing and
are reported through quality diagnostics; they are never inferred. A host map may
add the local host IP that native EVTX does not contain.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
import pathlib
from collections import Counter
from typing import Iterable
from xml.etree import ElementTree


SUPPORTED_CODES = {"4624", "4672", "4648"}
REQUIRED_FIELDS = {
    "4624": ("TargetUserName", "TargetLogonId", "IpAddress", "LogonType"),
    "4672": ("SubjectUserName", "SubjectLogonId"),
    "4648": ("SubjectUserName", "SubjectLogonId", "TargetUserName", "TargetServerName"),
}


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def evidence_descriptor(path: pathlib.Path, role: str) -> dict:
    stat = path.stat()
    return {
        "role": role,
        "file_name": path.name,
        "size_bytes": stat.st_size,
        "sha256": sha256_file(path),
        "modified_utc": dt.datetime.fromtimestamp(
            stat.st_mtime, tz=dt.timezone.utc
        ).isoformat().replace("+00:00", "Z"),
    }


def _unwrap(value) -> list[dict]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if not isinstance(value, dict):
        return []
    hits = value.get("hits")
    if isinstance(hits, dict) and isinstance(hits.get("hits"), list):
        records = []
        for hit in hits["hits"]:
            if not isinstance(hit, dict):
                continue
            source = hit.get("_source")
            if isinstance(source, dict):
                source = dict(source)
                if hit.get("_id") and not (source.get("event") or {}).get("id"):
                    source.setdefault("event", {})["id"] = str(hit["_id"])
                records.append(source)
        return records
    if isinstance(value.get("_source"), dict):
        return [value["_source"]]
    # Ignore Elasticsearch bulk-operation metadata lines.
    if set(value) & {"index", "create", "update", "delete"} and not (
        "event" in value or "winlog" in value
    ):
        return []
    return [value]


def load_json_records(path: pathlib.Path) -> list[dict]:
    """Load JSON, NDJSON, or an Elasticsearch search response."""
    if path.suffix.lower() in {".ndjson", ".jsonl"}:
        records = []
        with path.open(encoding="utf-8-sig") as handle:
            for line_no, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    records.extend(_unwrap(json.loads(line)))
                except json.JSONDecodeError as exc:
                    raise ValueError(f"{path.name}:{line_no}: invalid JSON: {exc}") from exc
        return records
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError:
        # Some tools use .json for newline-delimited exports.
        records = []
        with path.open(encoding="utf-8-sig") as handle:
            for line_no, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    records.extend(_unwrap(json.loads(line)))
                except json.JSONDecodeError as exc:
                    raise ValueError(f"{path.name}:{line_no}: invalid JSON: {exc}") from exc
        return records
    return _unwrap(value)


def _utc_timestamp(value: str) -> str:
    parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _event_data_from_xml(root: ElementTree.Element) -> dict:
    result = {}
    for node in root.findall(".//{*}EventData/{*}Data"):
        name = node.attrib.get("Name")
        if name:
            result[name] = node.text or ""
    return result


def load_evtx_records(path: pathlib.Path) -> list[dict]:
    try:
        from Evtx.Evtx import Evtx
    except ImportError as exc:  # pragma: no cover - explicit runtime diagnostic
        raise RuntimeError("EVTX support requires python-evtx; install requirements.txt") from exc

    records = []
    with Evtx(str(path)) as log:
        for record in log.records():
            root = ElementTree.fromstring(record.xml())
            code_node = root.find(".//{*}System/{*}EventID")
            code = (code_node.text or "") if code_node is not None else ""
            if code not in SUPPORTED_CODES:
                continue
            time_node = root.find(".//{*}System/{*}TimeCreated")
            computer_node = root.find(".//{*}System/{*}Computer")
            record_node = root.find(".//{*}System/{*}EventRecordID")
            timestamp = time_node.attrib.get("SystemTime") if time_node is not None else None
            computer = computer_node.text if computer_node is not None else None
            record_id = record_node.text if record_node is not None else str(record.record_num())
            event = {
                "@timestamp": _utc_timestamp(timestamp) if timestamp else None,
                "event": {"code": code, "id": f"evtx:{computer or 'unknown'}:{record_id}"},
                "host": {"name": computer} if computer else {},
                "winlog": {
                    "record_id": record_id,
                    "computer_name": computer,
                    "event_data": _event_data_from_xml(root),
                },
            }
            if code == "4624":
                event["event"]["outcome"] = "success"
            records.append(event)
    return records


def _canonical_ip(value):
    if value in (None, "", "-"):
        return value
    text = str(value).strip()
    try:
        parsed = ipaddress.ip_address(text)
        if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
            return str(parsed.ipv4_mapped)
        return str(parsed)
    except ValueError:
        return text


def _host_aliases(name: str | None) -> set[str]:
    if not name:
        return set()
    value = str(name).strip().rstrip(".").lower()
    return {value, value.split(".", 1)[0]}


def _reverse_host_map(ip_to_host: dict) -> dict[str, list[str]]:
    reverse: dict[str, list[str]] = {}
    for ip, name in ip_to_host.items():
        canonical_ip = _canonical_ip(ip)
        for alias in _host_aliases(str(name)):
            reverse.setdefault(alias, []).append(canonical_ip)
    return reverse


def normalize_windows_event(record: dict, ip_to_host: dict) -> dict | None:
    event = dict(record)
    event_meta = dict(event.get("event") or {})
    code = event_meta.get("code")
    if code is None:
        code = (event.get("winlog") or {}).get("event_id")
    code = str(code) if code is not None else ""
    if code not in SUPPORTED_CODES:
        return None

    winlog = dict(event.get("winlog") or {})
    data = dict(winlog.get("event_data") or {})
    host = dict(event.get("host") or {})
    host_name = host.get("name") or host.get("hostname") or winlog.get("computer_name")
    reverse = _reverse_host_map(ip_to_host)
    mapped_ips = []
    for alias in _host_aliases(host_name):
        mapped_ips.extend(reverse.get(alias, []))
    mapped_ips = list(dict.fromkeys(mapped_ips))

    existing_ips = host.get("ip")
    if isinstance(existing_ips, list):
        host_ips = [_canonical_ip(value) for value in existing_ips if value]
    elif existing_ips:
        host_ips = [_canonical_ip(existing_ips)]
    else:
        host_ips = mapped_ips

    # Prefer the canonical name declared in the analyst-provided map.
    for host_ip in host_ips:
        if host_ip in ip_to_host:
            host_name = ip_to_host[host_ip]
            break
    if host_name:
        host["name"] = host_name
    if host_ips:
        host["ip"] = host_ips[0] if len(host_ips) == 1 else host_ips

    if code == "4624":
        event_meta.setdefault("outcome", "success")
        if not data.get("IpAddress") and (event.get("source") or {}).get("ip"):
            data["IpAddress"] = (event.get("source") or {})["ip"]
        data["IpAddress"] = _canonical_ip(data.get("IpAddress"))

    timestamp = event.get("@timestamp") or event_meta.get("created")
    if timestamp:
        event["@timestamp"] = _utc_timestamp(timestamp)
    event_meta["code"] = code
    if not event_meta.get("id"):
        record_id = winlog.get("record_id") or event_meta.get("sequence")
        if record_id is not None:
            event_meta["id"] = f"windows:{host_name or 'unknown'}:{record_id}"
    event["event"] = event_meta
    event["host"] = host
    winlog["event_data"] = data
    event["winlog"] = winlog
    return event


def _quality_issue(event: dict) -> list[str]:
    issues = []
    code = str((event.get("event") or {}).get("code") or "")
    data = (event.get("winlog") or {}).get("event_data") or {}
    if not event.get("@timestamp"):
        issues.append("missing @timestamp")
    host = event.get("host") or {}
    if not host.get("name"):
        issues.append("missing host.name")
    if not host.get("ip"):
        issues.append("missing host.ip (provide an IP-to-host map for native EVTX)")
    for field in REQUIRED_FIELDS.get(code, ()):
        if data.get(field) in (None, "", "-"):
            issues.append(f"missing winlog.event_data.{field}")
    return issues


def load_windows_sources(paths: Iterable[pathlib.Path], ip_to_host: dict) -> tuple[list[dict], dict]:
    events = []
    by_code = Counter()
    issues = Counter()
    source_stats = []
    raw_total = 0
    for path in paths:
        suffix = path.suffix.lower()
        raw = load_evtx_records(path) if suffix == ".evtx" else load_json_records(path)
        raw_total += len(raw)
        accepted = 0
        for record in raw:
            event = normalize_windows_event(record, ip_to_host)
            if event is None:
                continue
            accepted += 1
            code = str((event.get("event") or {}).get("code"))
            by_code[code] += 1
            for issue in _quality_issue(event):
                issues[f"{code}: {issue}"] += 1
            events.append(event)
        source_stats.append({"file_name": path.name, "raw_records": len(raw), "accepted_records": accepted})
    events.sort(key=lambda item: item.get("@timestamp") or "")
    return events, {
        "raw_records": raw_total,
        "recognized_windows_events": len(events),
        "by_event_code": dict(sorted(by_code.items())),
        "quality_issues": dict(sorted(issues.items())),
        "sources": source_stats,
    }
