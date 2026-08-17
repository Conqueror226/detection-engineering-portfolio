#!/usr/bin/env python3
"""Materialize evidence-supported PivotEdges from raw ECS + Windows events.

Only emits an edge when the evidence supports it:

  service      network.destination.port + 4624 LogonType must be COMPATIBLE
               (tcp/3389+LogonType10->rdp; tcp/445+LogonType3->smb). Among all
               candidate flows the nearest COMPATIBLE one is chosen, so a newer
               unrelated flow (e.g. HTTPS) cannot hide valid RDP evidence.
  reached      network.destination.ip in 4624 host.ip (array-valued host.ip ok)
  from         network.source.ip == 4624 IpAddress
  privileged   4672 SubjectLogonId==4624 TargetLogonId, same host/principal,
               bounded ordered time; the real 4672 event.id is recorded.
  transition   a 4648 on the SOURCE host with a NON-EMPTY SubjectLogonId whose
               TargetUserName is this edge's identity and TargetServerName its
               target -> attaches to THIS (outgoing) edge with source_logon_id
               lineage. If several DISTINCT sessions are plausible, the transition
               is left UNCONFIRMED (state "unknown" -> INSUFFICIENT_EVIDENCE) rather
               than arbitrarily selecting one.

Identity is DOMAIN\\user. Duplicate logons are idempotent. Missing event.id yields
a deterministic reference derived from the raw record — never an invented literal.
Events are pre-indexed and timestamps precomputed once per bucket.
"""
from __future__ import annotations

import bisect
import datetime
import hashlib
import json
from collections import defaultdict

SERVICE_BY_LOGON = {("3389", "10"): "rdp", ("445", "3"): "smb"}


def _ts(e): return datetime.datetime.fromisoformat(e["@timestamp"].replace("Z", "+00:00"))
def _ed(e): return (e.get("winlog", {}) or {}).get("event_data", {}) or {}
def _code(e):
    value = (e.get("event", {}) or {}).get("code")
    return str(value) if value is not None else None
def _cats(e):
    c = (e.get("event", {}) or {}).get("category")
    return c if isinstance(c, list) else [c] if c else []
def _is_network(e): return "network" in _cats(e)


def _ref(e) -> str:
    """Stable evidence reference: the event.id if present, else a deterministic
    hash of the raw record (never an invented literal like 'net'/'4624')."""
    eid = (e.get("event", {}) or {}).get("id")
    if eid:
        return eid
    return "raw-" + hashlib.sha256(json.dumps(e, sort_keys=True, default=str).encode()).hexdigest()[:16]


def _host_ips(e) -> set:
    hip = (e.get("host", {}) or {}).get("ip")
    if isinstance(hip, list):
        return set(hip)
    return {hip} if hip else set()


def _norm_identity(user, domain):
    if not user:
        return user
    if "\\" in user or "@" in user:
        return user
    return f"{domain}\\{user}" if domain else user


def _host_aliases(value) -> set[str]:
    if not value:
        return set()
    name = str(value).strip().rstrip(".").lower()
    return {name, name.split(".", 1)[0]}


def _host_equivalent(observed, target_host, target_ip, ip_to_host) -> bool:
    """Match DNS short/FQDN/IP representations without inventing a host link."""
    if not observed:
        return False
    observed_text = str(observed).strip()
    if observed_text == target_ip:
        return True
    aliases = _host_aliases(observed_text)
    aliases |= _host_aliases(ip_to_host.get(observed_text))
    target_aliases = _host_aliases(target_host)
    target_aliases |= _host_aliases(ip_to_host.get(target_ip))
    return bool(aliases & target_aliases)


def _edge_id(*parts) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:16]


def materialize(events, ip_to_host=None, network_window_s=120,
                priv_window_s=60, transition_window_s=300):
    ip_to_host = ip_to_host or {}
    logons = [e for e in events if _code(e) == "4624" and (e.get("event", {}) or {}).get("outcome") == "success"]
    privs = [e for e in events if _code(e) == "4672"]
    creds = [e for e in events if _code(e) == "4648"]
    nets = [e for e in events if _is_network(e)]              # membership, not [0]

    # indexes, timestamps precomputed once per bucket
    nets_by_src: dict = defaultdict(list)
    for n in nets:
        nets_by_src[(n.get("source", {}) or {}).get("ip")].append(n)
    net_index = {}
    for src, lst in nets_by_src.items():
        lst.sort(key=_ts)
        net_index[src] = (lst, [_ts(n) for n in lst])
    priv_by_lid = defaultdict(list)
    for p in privs:
        priv_by_lid[_ed(p).get("SubjectLogonId")].append(p)
    creds_by_host = defaultdict(list)
    for c in creds:
        for hip in _host_ips(c):
            creds_by_host[hip].append(c)

    edges = {}
    for lg in logons:
        d = _ed(lg)
        host_ips = _host_ips(lg)
        src_ip = d.get("IpAddress")
        target_host = (lg.get("host", {}) or {}).get("name")
        user = _norm_identity(d.get("TargetUserName"), d.get("TargetDomainName"))
        logon_id = d.get("TargetLogonId")
        logon_type = str(d.get("LogonType", ""))
        t_logon = _ts(lg)

        # nearest COMPATIBLE network flow (service compatibility drives selection)
        net = target_ip = service = None
        cand, ts_list = net_index.get(src_ip, ([], []))
        hi = bisect.bisect_right(ts_list, t_logon)
        for j in range(hi - 1, -1, -1):
            if (t_logon - ts_list[j]).total_seconds() > network_window_s:
                break
            n = cand[j]
            dip = (n.get("destination", {}) or {}).get("ip")
            if dip not in host_ips:
                continue
            svc = SERVICE_BY_LOGON.get((str((n.get("destination", {}) or {}).get("port")), logon_type))
            if svc is not None:
                net, target_ip, service = n, dip, svc
                break
        if net is None:
            continue

        # privilege: same session, principal, bounded ordered time
        priv_ev = None
        for p in priv_by_lid.get(logon_id, []):
            pd = _ed(p)
            if host_ips & _host_ips(p) \
               and _norm_identity(pd.get("SubjectUserName"), pd.get("SubjectDomainName")) == user \
               and 0 <= (_ts(p) - t_logon).total_seconds() <= priv_window_s:
                priv_ev = p
                break

        # credential transition on the SOURCE host -> outgoing edge; deterministic + abstaining
        ct = None
        source_logon_id = None
        cred_cands = []
        for c in creds_by_host.get(src_ip, []):
            cd = _ed(c)
            slid = cd.get("SubjectLogonId")
            to_id = _norm_identity(cd.get("TargetUserName"), cd.get("TargetDomainName"))
            if slid and to_id == user \
               and _host_equivalent(cd.get("TargetServerName"), target_host, target_ip, ip_to_host) \
               and 0 <= (t_logon - _ts(c)).total_seconds() <= transition_window_s:
                cred_cands.append(c)
        cred_cands.sort(key=_ts)
        distinct_sessions = {_ed(c).get("SubjectLogonId") for c in cred_cands}
        if len(cred_cands) >= 1 and len(distinct_sessions) == 1:
            c = cred_cands[0]; cd = _ed(c)
            ct = {"from_identity": _norm_identity(cd.get("SubjectUserName"), cd.get("SubjectDomainName")),
                  "to_identity": user, "state": "confirmed", "evidence_ref": _ref(c)}
            source_logon_id = cd.get("SubjectLogonId")
        elif len(distinct_sessions) > 1:
            # ambiguous: multiple plausible sessions -> do not confirm
            c = cred_cands[0]; cd = _ed(c)
            ct = {"from_identity": _norm_identity(cd.get("SubjectUserName"), cd.get("SubjectDomainName")),
                  "to_identity": user, "state": "unknown", "evidence_ref": _ref(c)}

        eff = ct["to_identity"] if (ct and ct["state"] == "confirmed") else user
        edge_id = _edge_id(target_host, user, logon_id, lg["@timestamp"], src_ip)
        if edge_id in edges:
            continue
        edges[edge_id] = {
            "edge_id": edge_id, "@timestamp": lg["@timestamp"],
            "source_host": ip_to_host.get(src_ip, src_ip), "source_ip": src_ip,
            "target_host": target_host, "target_ip": target_ip, "identity": user,
            "effective_identity": eff, "service": service, "logon_id": logon_id,
            "source_logon_id": source_logon_id,
            "privilege_state": "confirmed" if priv_ev else "absent",
            "auth_state": "confirmed", "credential_transition": ct,
            "evidence_refs": {"network": _ref(net), "logon": _ref(lg),
                              "privilege": _ref(priv_ev) if priv_ev else None},
        }
    return list(edges.values())


def main() -> int:
    import sys
    if len(sys.argv) < 2:
        print("usage: materialize_pivot_edges.py <raw_events.json> [ip_to_host.json]"); return 2
    events = json.loads(open(sys.argv[1]).read())
    ip_map = json.loads(open(sys.argv[2]).read()) if len(sys.argv) > 2 else {}
    print(json.dumps(materialize(events, ip_map), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
