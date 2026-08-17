#!/usr/bin/env python3
"""Materializer: positive controls + the negative cases from the v8 review."""
from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from materialize_pivot_edges import materialize  # noqa: E402

IPMAP = {"10.0.0.10": "WS-ENG-12", "10.0.0.60": "SRV-APP-01"}
HOST, SRC = "10.0.0.60", "10.0.0.10"

def net(dport, t="10:00:00", src=SRC, dst=HOST):
    return {"@timestamp": f"2026-08-10T{t}Z", "event": {"category": ["network"], "id": "n1"},
            "source": {"ip": src}, "destination": {"ip": dst, "port": dport}}
def logon(lt, user="CORP\\bob", lid="0x111", t="10:00:30", host_ip=HOST, ipaddr=SRC, host="SRV-APP-01"):
    return {"@timestamp": f"2026-08-10T{t}Z" if len(t) == 8 else t,
            "event": {"code": "4624", "outcome": "success", "id": "l1"},
            "host": {"ip": host_ip, "name": host},
            "winlog": {"event_data": {"TargetUserName": user, "TargetLogonId": lid,
                                      "IpAddress": ipaddr, "LogonType": lt}}}
def priv(lid, user="CORP\\bob", t="10:00:31", host_ip=HOST, eid="p-real-1"):
    return {"@timestamp": f"2026-08-10T{t}Z" if len(t) == 8 else t, "event": {"code": "4672", "id": eid},
            "host": {"ip": host_ip}, "winlog": {"event_data": {"SubjectLogonId": lid, "SubjectUserName": user}}}


def main() -> int:
    fails = []
    priv_edges = lambda ev: [e for e in materialize(ev, IPMAP) if e["privilege_state"] == "confirmed"]
    all_edges = lambda ev: materialize(ev, IPMAP)

    # positive: RDP (3389 + LogonType 10) -> one privileged rdp edge, real 4672 id
    ok = priv_edges([net(3389), logon("10"), priv("0x111")])
    if not (len(ok) == 1 and ok[0]["service"] == "rdp" and ok[0]["evidence_refs"]["privilege"] == "p-real-1"):
        fails.append(f"RDP positive control wrong: {ok}")
    # positive: SMB (445 + LogonType 3)
    smb = all_edges([net(445), logon("3"), priv("0x111")])
    if not (len(smb) == 1 and smb[0]["service"] == "smb"):
        fails.append(f"SMB positive control wrong: {smb}")

    negatives = {
        "https+interactive (443/LogonType10)": [net(443), logon("10"), priv("0x111")],
        "rdp port + network logon (3389/3)":   [net(3389), logon("3"), priv("0x111")],
        "wrong auth source IP":                 [net(3389), logon("10", ipaddr="10.9.9.9"), priv("0x111")],
        "stale 4672 (2019)":                    [net(3389), logon("10"), priv("0x111", t="2019-01-01T00:00:00Z")],
        "mismatched logon IDs":                 [net(3389), logon("10", lid="0x111"), priv("0x999")],
        "different 4624/4672 users":            [net(3389), logon("10"), priv("0x111", user="CORP\\eve")],
    }
    for name, ev in negatives.items():
        if priv_edges(ev):
            fails.append(f"'{name}' wrongly produced a privileged edge")
    # port/logon-incompatible must produce NO edge at all
    for name in ("https+interactive (443/LogonType10)", "rdp port + network logon (3389/3)"):
        if all_edges(negatives[name]):
            fails.append(f"'{name}' wrongly produced an edge")

    # host.ip as an ARRAY (ECS-legal) must still match
    arr = logon("10"); arr["host"]["ip"] = ["10.0.0.60", "fe80::1"]
    if len(all_edges([net(3389), arr, priv("0x111")])) != 1:
        fails.append("array-valued host.ip was missed")

    # duplicate raw 4624 -> a single edge
    lg = logon("10")
    if len(all_edges([net(3389), lg, dict(lg)])) != 1:
        fails.append("duplicate 4624 ingestion was not de-duplicated")

    # 4648 attaches to the OUTGOING hop (B->C), not the incoming (A->B)
    ev = [net(3389, src=SRC, dst=HOST), logon("10", lid="0xA1"), priv("0xA1"),
          net(3389, src=HOST, dst="10.0.0.90", t="10:01:00"),
          logon("10", user="CORP\\dom_admin", lid="0xB2", t="10:01:30", host_ip="10.0.0.90",
                ipaddr=HOST, host="DC01"),
          {"@timestamp": "2026-08-10T10:00:50Z", "event": {"code": "4648", "id": "c-real-1"},
           "host": {"ip": HOST}, "winlog": {"event_data": {"SubjectLogonId": "0xA1",
           "SubjectUserName": "CORP\\bob", "TargetUserName": "CORP\\dom_admin", "TargetServerName": "DC01"}}}]
    edges = materialize(ev, {**IPMAP, "10.0.0.90": "DC01"})
    ab = [e for e in edges if e["target_host"] == "SRV-APP-01"]
    bc = [e for e in edges if e["target_host"] == "DC01"]
    if ab and ab[0]["credential_transition"] is not None:
        fails.append("transition wrongly attached to the incoming A->B edge")
    if not (bc and bc[0]["credential_transition"] and bc[0]["source_logon_id"] == "0xA1"):
        fails.append(f"transition not on outgoing B->C edge with lineage: {bc}")

    # Real Windows logs frequently record TargetServerName as an FQDN while
    # host.name/context use the short name; the two representations must join.
    fqdn_ev = list(ev)
    fqdn_cred = dict(fqdn_ev[-1])
    fqdn_cred["winlog"] = {"event_data": dict(fqdn_ev[-1]["winlog"]["event_data"])}
    fqdn_cred["winlog"]["event_data"]["TargetServerName"] = "dc01.corp.example"
    fqdn_ev[-1] = fqdn_cred
    fqdn_edges = materialize(fqdn_ev, {**IPMAP, "10.0.0.90": "DC01"})
    fqdn_bc = [e for e in fqdn_edges if e["target_host"] == "DC01"]
    if not (fqdn_bc and fqdn_bc[0]["credential_transition"]
            and fqdn_bc[0]["credential_transition"]["state"] == "confirmed"):
        fails.append("FQDN TargetServerName did not match canonical short host name")

    # RDP evidence must not be hidden by a NEWER unrelated HTTPS flow to same host
    ev = [net(3389, "10:00:00"), net(443, "10:00:20"), logon("10"), priv("0x111")]
    if len(all_edges(ev)) != 1:
        fails.append("newer HTTPS flow hid valid RDP evidence")
    # ECS category with 'network' not first must still be seen
    n2 = net(3389); n2["event"]["category"] = ["event", "network"]
    if len(all_edges([n2, logon("10"), priv("0x111")])) != 1:
        fails.append("category ['event','network'] was ignored")
    # A->B->C helper for 4648 cases
    def abc(cred_extra):
        base = [net(3389, src=SRC, dst=HOST), logon("10", lid="0xA1"), priv("0xA1"),
                net(3389, src=HOST, dst="10.0.0.90", t="10:01:00"),
                logon("10", user="CORP\\dom_admin", lid="0xB2", t="10:01:30", host_ip="10.0.0.90",
                      ipaddr=HOST, host="DC01")]
        return materialize(base + cred_extra, {**IPMAP, "10.0.0.90": "DC01"})
    def c4648(slid, eid="c1"):
        d = {"SubjectUserName": "CORP\\bob", "TargetUserName": "CORP\\dom_admin", "TargetServerName": "DC01"}
        if slid is not None:
            d["SubjectLogonId"] = slid
        return {"@timestamp": "2026-08-10T10:00:50Z", "event": {"code": "4648", "id": eid},
                "host": {"ip": HOST}, "winlog": {"event_data": d}}
    # 4648 with MISSING SubjectLogonId -> no confirmed transition
    bc = [e for e in abc([c4648(None)]) if e["target_host"] == "DC01"]
    if bc and bc[0]["credential_transition"] and bc[0]["credential_transition"]["state"] == "confirmed":
        fails.append("4648 with missing SubjectLogonId was confirmed")
    # ambiguous: two DISTINCT plausible sessions -> unconfirmed (abstain)
    bc = [e for e in abc([c4648("0xA1", "c1"), c4648("0xZZ", "c2")]) if e["target_host"] == "DC01"]
    ct = bc[0]["credential_transition"] if bc else None
    if not (ct and ct["state"] == "unknown"):
        fails.append(f"ambiguous 4648 sessions were not abstained: {ct}")

    if fails:
        print("[FAIL] edge materialization")
        for f in fails:
            print(f"       - {f}")
        return 1
    print("[PASS] edge materialization: service/logon compat, 4672 time-bound, 4648 outgoing-hop, "
          "host.ip arrays, dedup, negatives all correct")
    return 0


if __name__ == "__main__":
    sys.exit(main())
