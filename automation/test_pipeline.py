#!/usr/bin/env python3
"""End-to-end pipeline tests: raw telemetry -> materializer -> graph -> finding.

  Case 1 (pcap): a privileged progression to a DC over an unapproved route
                 reconstructs as CRITICAL_UNAPPROVED_PATH.
  Case 2 (raw):  an explicit-credential (4648) hop reconstructs as
                 CREDENTIAL_TRANSITION_PROGRESSION with the transition on the
                 OUTGOING edge and session lineage.
"""
from __future__ import annotations

import io
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "automation"))
sys.path.insert(0, str(ROOT / "sensor"))
PIPE = ROOT / "fixtures" / "pipeline"

import sensor as sensor_mod  # noqa: E402
from scapy.all import rdpcap  # noqa: E402
from materialize_pivot_edges import materialize  # noqa: E402
from build_reachability_graph import ReachabilityGraph  # noqa: E402
from classify_pivot_progression import classify, load_context  # noqa: E402


def case_pcap(failures):
    buf = io.StringIO()
    sensor_mod.run(rdpcap(str(PIPE / "privileged_unapproved_path.pcap")), "sensor-host", buf)
    net_events = [json.loads(l) for l in buf.getvalue().splitlines() if l.strip()]
    win = json.loads((PIPE / "windows_events.json").read_text())
    ip_map = json.loads((PIPE / "ip_to_host.json").read_text())
    edges = materialize(net_events + win, ip_map)
    labels = [(f["label"], tuple(f["path"])) for f in classify(ReachabilityGraph.from_records(edges), load_context())]
    if len(edges) != 2:
        failures.append(f"pcap case: expected 2 edges, got {len(edges)}")
    want = ("CRITICAL_UNAPPROVED_PATH", ("WS-ENG-12", "SRV-APP-01", "DC01"))
    if want not in labels:
        failures.append(f"pcap case: expected {want}, got {labels}")


def case_credential_transition(failures):
    def net(src, dst, port, t):
        return {"@timestamp": f"2026-08-10T{t}Z", "event": {"category": ["network"], "id": f"n-{src}-{dst}"},
                "source": {"ip": src}, "destination": {"ip": dst, "port": port}}
    def logon(hip, ipa, user, lid, t, host, lt):
        return {"@timestamp": f"2026-08-10T{t}Z", "event": {"code": "4624", "outcome": "success", "id": f"l-{lid}"},
                "host": {"ip": hip, "name": host},
                "winlog": {"event_data": {"TargetUserName": user, "TargetLogonId": lid, "IpAddress": ipa, "LogonType": lt}}}
    def priv(hip, lid, user, t):
        return {"@timestamp": f"2026-08-10T{t}Z", "event": {"code": "4672", "id": f"p-{lid}"},
                "host": {"ip": hip}, "winlog": {"event_data": {"SubjectLogonId": lid, "SubjectUserName": user}}}
    BOB, DA = "CORP\\bob", "CORP\\dom_admin"
    events = [
        net("10.0.0.10", "10.0.0.60", 3389, "10:00:00"),
        logon("10.0.0.60", "10.0.0.10", BOB, "0xA1", "10:00:30", "SRV-APP-01", "10"),
        priv("10.0.0.60", "0xA1", BOB, "10:00:31"),
        {"@timestamp": "2026-08-10T10:00:50Z", "event": {"code": "4648", "id": "c-42"},
         "host": {"ip": "10.0.0.60"}, "winlog": {"event_data": {"SubjectLogonId": "0xA1",
          "SubjectUserName": BOB, "TargetUserName": DA, "TargetServerName": "SRV-FILE-02"}}},
        net("10.0.0.60", "10.0.0.70", 445, "10:01:00"),
        logon("10.0.0.70", "10.0.0.60", DA, "0xB2", "10:01:30", "SRV-FILE-02", "3"),
        priv("10.0.0.70", "0xB2", DA, "10:01:31"),
    ]
    ip_map = {"10.0.0.10": "WS-ENG-12", "10.0.0.60": "SRV-APP-01", "10.0.0.70": "SRV-FILE-02"}
    edges = materialize(events, ip_map)
    bc = [e for e in edges if e["target_host"] == "SRV-FILE-02"]
    if not (bc and bc[0]["credential_transition"] and bc[0]["source_logon_id"] == "0xA1"):
        failures.append(f"ct case: transition/lineage not on outgoing edge: {bc}")
    labels = [(f["label"], tuple(f["path"])) for f in classify(ReachabilityGraph.from_records(edges), load_context())]
    want = ("CREDENTIAL_TRANSITION_PROGRESSION", ("WS-ENG-12", "SRV-APP-01", "SRV-FILE-02"))
    if want not in labels:
        failures.append(f"ct case: expected {want}, got {labels}")


def main() -> int:
    failures = []
    case_pcap(failures)
    case_credential_transition(failures)
    if failures:
        print("[FAIL] pipeline")
        for f in failures:
            print(f"       - {f}")
        return 1
    print("[PASS] pipeline: pcap->CRITICAL_UNAPPROVED_PATH; raw+4648->CREDENTIAL_TRANSITION_PROGRESSION")
    return 0


if __name__ == "__main__":
    sys.exit(main())
