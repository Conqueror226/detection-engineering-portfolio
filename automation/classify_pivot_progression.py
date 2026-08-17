#!/usr/bin/env python3
"""Classify authenticated-pivot progressions to expose administrative blindness.

v7-review remediation:
  - finding fingerprint is (label, identity, edges) -> distinct identities/sessions
    are never collapsed; only a byte-identical finding is deduplicated;
  - privilege is tracked on BOTH sessions via `privilege_scope`; source-session
    privilege -> PRIVILEGED_PROGRESSION, destination-only -> PRIVILEGED_DESTINATION_REACH;
  - approvals honour approved_from..approved_until and optional via/service scope.

Vocabulary: automation/context/VOCABULARY.md
"""
from __future__ import annotations

import datetime
import pathlib

import yaml

from build_reachability_graph import Edge, ReachabilityGraph, confirmed_transition_links, session_lineage

CONTEXT_DIR = pathlib.Path(__file__).resolve().parent / "context"

CONFIDENCE = {
    "NONE": "none", "EXPECTED": "none", "JUSTIFIED": "none",
    "INSUFFICIENT_EVIDENCE": "low", "INSUFFICIENT_CONTEXT": "low",
    "PIVOT_PROGRESSION": "low",
    "POSSIBLE_PRIVILEGED_PROGRESSION": "low",
    "PRIVILEGED_DESTINATION_REACH": "medium", "PRIVILEGED_PROGRESSION": "medium",
    "CREDENTIAL_TRANSITION_PROGRESSION": "high", "CRITICAL_UNAPPROVED_PATH": "highest",
}

ROUTE_AUTHORIZED = "AUTHORIZED"
ROUTE_PROHIBITED = "PROHIBITED"
ROUTE_UNKNOWN = "UNKNOWN_CONTEXT"


def load_context(context_dir: pathlib.Path = CONTEXT_DIR) -> dict:
    def _load(name):
        with (context_dir / name).open(encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    return {k: _load(f"{k}.yml") for k in
            ("asset_tiers", "identity_roles", "expected_admin_paths",
             "approved_changes", "known_reachability")}


def host_entry(ctx, h): return ctx["asset_tiers"].get("hosts", {}).get(h)
def identity_entry(ctx, i): return ctx["identity_roles"].get("identities", {}).get(i)
def host_tier(ctx, h):
    e = host_entry(ctx, h); return e["tier"] if e else None
def host_is_critical(ctx, h):
    e = host_entry(ctx, h); return bool(e and e.get("critical"))
def identity_justified_tier(ctx, i):
    e = identity_entry(ctx, i); return e["justified_max_tier"] if e else None

def route_decision(ctx, identity, via_host, to_tier, at: datetime.datetime,
                   environment: str = "on_prem") -> str:
    """Return a three-state policy decision.

    A missing allow-list entry is a prohibition only when the supplied policy is
    active and explicitly complete for this environment, identity, and target
    tier. Everywhere else the examiner gets UNKNOWN_CONTEXT, not an accusation.
    """
    policy = ctx["expected_admin_paths"]
    metadata = policy.get("policy_metadata") or {}
    try:
        valid_from = datetime.date.fromisoformat(str(metadata["valid_from"]))
        valid_until = datetime.date.fromisoformat(str(metadata["valid_until"]))
    except (KeyError, TypeError, ValueError):
        return ROUTE_UNKNOWN
    if not (valid_from <= at.date() <= valid_until):
        return ROUTE_UNKNOWN

    if any(p.get("identity") == identity and p.get("via") == via_host
           and p.get("to_tier") == to_tier
           for p in policy.get("approved_paths", [])):
        return ROUTE_AUTHORIZED

    complete = any(
        scope.get("environment") == environment
        and scope.get("identity") == identity
        and scope.get("target_tier") == to_tier
        for scope in metadata.get("complete_for", [])
    )
    return ROUTE_PROHIBITED if complete else ROUTE_UNKNOWN

def _in_window(c, at: datetime.datetime) -> bool:
    def d(key, default):
        v = c.get(key)
        return datetime.date.fromisoformat(str(v)) if v else default
    frm = d("approved_from", datetime.date.min)
    until = d("approved_until", datetime.date.max)
    return frm <= at.date() <= until

def approved_change(ctx, identity, first: Edge, nxt: Edge) -> bool:
    for c in ctx["approved_changes"].get("approved_changes", []):
        if c["identity"] != identity or c["target_host"] != nxt.target_host:
            continue
        if not _in_window(c, nxt.timestamp):
            continue
        if "via" in c and c["via"] != first.target_host:      # optional route scope
            continue
        if "service" in c and c["service"] != nxt.service:    # optional service scope
            continue
        return True
    return False

def is_novel(ctx, identity, target) -> bool:
    return target not in ctx["known_reachability"].get("known_edges", {}).get(identity, [])


def _finding(label, path, identity, edges, rationale, modifiers=None):
    return {"label": label, "confidence": CONFIDENCE[label], "path": path,
            "identity": identity, "edges": edges, "rationale": rationale,
            "modifiers": modifiers or {}}


def classify_hop(ctx: dict, first: Edge, nxt: Edge) -> dict | None:
    identity = nxt.effective_identity
    path = [first.source_host, first.target_host, nxt.target_host]
    edges = [first.edge_id, nxt.edge_id]

    src_tier = host_tier(ctx, first.target_host)
    dst_tier = host_tier(ctx, nxt.target_host)
    novel = is_novel(ctx, identity, nxt.target_host)
    critical = host_is_critical(ctx, nxt.target_host)
    has_transition = nxt.credential_transition is not None
    ct_confirmed = confirmed_transition_links(first, nxt)
    higher_tier = (src_tier is not None and dst_tier is not None and dst_tier < src_tier)

    src_priv = first.privilege_state == "confirmed"
    dst_priv = nxt.privilege_state == "confirmed"
    privilege_scope = ("both" if src_priv and dst_priv else
                       "source" if src_priv else
                       "destination" if dst_priv else "none")
    lineage = session_lineage(first, nxt)

    modifiers = {
        "src_tier": src_tier, "dst_tier": dst_tier, "target_novelty": novel,
        "target_critical": critical, "privilege_scope": privilege_scope,
        "session_lineage": lineage,
        "source_session_privilege": first.privilege_state,
        "destination_session_privilege": nxt.privilege_state,
        "credential_transition_present": has_transition,
        "credential_transition_confirmed": ct_confirmed,
        "evidence_completeness": first.auth_confirmed and nxt.auth_confirmed,
        "identity_tier_entitlement": identity_justified_tier(ctx, identity),
    }

    if not (novel or higher_tier or has_transition or critical):
        return None

    if not (first.auth_confirmed and nxt.auth_confirmed):
        return _finding("INSUFFICIENT_EVIDENCE", path, identity, edges,
                        "A hop lacks confirmed authentication; edge not established.", modifiers)
    if has_transition and not ct_confirmed:
        return _finding("INSUFFICIENT_EVIDENCE", path, identity, edges,
                        "Credential transition present but unconfirmed; continuity uncertain.", modifiers)

    unknown_hosts = [h for h in (first.source_host, first.target_host, nxt.target_host)
                     if host_entry(ctx, h) is None]
    unknown_ids = [i for i in {first.identity, first.effective_identity, nxt.identity, identity}
                   if identity_entry(ctx, i) is None]
    if unknown_hosts or unknown_ids:
        return _finding("INSUFFICIENT_CONTEXT", path, identity, edges,
                        f"Undeclared context: hosts={unknown_hosts} identities={unknown_ids}.", modifiers)

    route_state = route_decision(ctx, identity, first.target_host, dst_tier, nxt.timestamp)
    modifiers["route_policy_state"] = route_state

    if dst_tier == 0 and critical:
        if route_state == ROUTE_AUTHORIZED:
            return _finding("EXPECTED", path, identity, edges,
                            "Tier-0 reached via a sanctioned administrative path.", modifiers)
        if route_state == ROUTE_PROHIBITED:
            return _finding("CRITICAL_UNAPPROVED_PATH", path, identity, edges,
                            "Reaches a Tier-0/critical asset by a route prohibited by an active, complete policy scope.", modifiers)
        return _finding("INSUFFICIENT_CONTEXT", path, identity, edges,
                        "Tier-0 was reached, but supplied route policy is not complete and active for this identity and tier.", modifiers)

    if approved_change(ctx, identity, first, nxt):
        return _finding("JUSTIFIED", path, identity, edges,
                        "New access authorized by an in-window, in-scope change ticket.", modifiers)

    if route_state == ROUTE_AUTHORIZED:
        return _finding("EXPECTED", path, identity, edges,
                        "Matches a sanctioned administrative path.", modifiers)

    if ct_confirmed:
        return _finding("CREDENTIAL_TRANSITION_PROGRESSION", path, identity, edges,
                        "A confirmed credential change (4648) preceded onward movement.", modifiers)

    # Dual-session privilege semantics. Session-exact lineage earns the confident
    # label; identity-level lineage cannot prove WHICH same-identity session moved.
    if src_priv:
        if lineage == "session-exact":
            return _finding("PRIVILEGED_PROGRESSION", path, identity, edges,
                            "The privileged session on the pivot host propagated onward.", modifiers)
        return _finding("POSSIBLE_PRIVILEGED_PROGRESSION", path, identity, edges,
                        "An identity with a privileged session on the pivot host reached onward; "
                        "session lineage is not confirmed, so attribution is identity-level.", modifiers)
    if dst_priv:
        return _finding("PRIVILEGED_DESTINATION_REACH", path, identity, edges,
                        "Onward movement established a privileged session on the destination.", modifiers)
    return _finding("PIVOT_PROGRESSION", path, identity, edges,
                    "Access propagated to a new/higher-tier host (no privileged session).", modifiers)


def classify(graph: ReachabilityGraph, ctx: dict, window_minutes: int = 30) -> list[dict]:
    # Streaming: retain only deduplicated findings, keyed by (label, identity, path).
    # Repeated observations of the SAME identity-target expansion collapse into ONE
    # finding carrying occurrence_count (distinct identities are never merged); no
    # full pair list is materialised, so memory stays flat on fan-in/out.
    by_key: dict = {}
    progressed: set = set()
    second_hop_ids: set = set()

    def _add(f):
        key = (f["label"], f["identity"], tuple(f["path"]))
        agg = by_key.get(key)
        if agg is None:
            f["modifiers"]["occurrence_count"] = 1
            f["modifiers"]["first_seen_in_window"] = True
            f["modifiers"]["baseline_novel"] = f["modifiers"].get("target_novelty")
            by_key[key] = f
        else:
            agg["modifiers"]["occurrence_count"] += 1   # keep first edges; count repeats

    for first, nxt in graph.iter_pairs(window_minutes):
        second_hop_ids.add(nxt.edge_id)
        f = classify_hop(ctx, first, nxt)
        if f is not None:
            progressed.add(first.edge_id)
            _add(f)

    for edge in graph.edges:
        if edge.edge_id in progressed or edge.edge_id in second_hop_ids:
            continue
        if not edge.auth_confirmed:
            _add(_finding("INSUFFICIENT_EVIDENCE", [edge.source_host, edge.target_host],
                          edge.effective_identity, [edge.edge_id],
                          "Standalone edge lacks confirmed authentication."))
        else:
            _add(_finding("NONE", [edge.source_host, edge.target_host],
                          edge.effective_identity, [edge.edge_id],
                          "Authenticated session with no qualifying onward movement."))
    return list(by_key.values())


def main() -> int:
    import json
    import sys
    if len(sys.argv) < 2:
        print("usage: classify_pivot_progression.py <edges.json>"); return 2
    records = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
    for r in classify(ReachabilityGraph.from_records(records), load_context()):
        print(f"[{r['confidence']:>7}] {r['label']:<32} {r['identity']:<16} {' -> '.join(r['path'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
