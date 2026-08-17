#!/usr/bin/env python3
"""Edge-contract invariants: forged identity and duplicate ids are handled safely."""
from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from build_reachability_graph import Edge, ReachabilityGraph  # noqa: E402
from classify_pivot_progression import classify, load_context  # noqa: E402


def _rec(eid, src, dst, ident, eff, ct=None, t="10:00:00"):
    return {"edge_id": eid, "@timestamp": f"2026-08-10T{t}Z", "source_host": src, "target_host": dst,
            "identity": ident, "effective_identity": eff, "service": "rdp", "logon_id": "0x1",
            "privilege_state": "confirmed", "auth_state": "confirmed",
            "credential_transition": ct, "evidence_refs": {"logon": "l"}}


def main() -> int:
    fails = []
    DA = "CORP\\dom_admin"; ALICE = "CORP\\alice"

    # 1. forged effective_identity (no transition) must be coerced -> no false continuity/CRITICAL
    recs = [_rec("z1", "WS-ENG-12", "SRV-APP-01", ALICE, DA),                    # claims DA, ct null
            _rec("z2", "SRV-APP-01", "DC01", DA, DA, t="10:05:00")]
    labels = {f["label"] for f in classify(ReachabilityGraph.from_records(recs), load_context())}
    if "CRITICAL_UNAPPROVED_PATH" in labels:
        fails.append("forged effective_identity produced CRITICAL_UNAPPROVED_PATH")

    # 2. duplicate edge_id must raise
    try:
        ReachabilityGraph.from_records([_rec("dup", "A", "B", ALICE, ALICE),
                                        _rec("dup", "B", "C", ALICE, ALICE, t="10:02:00")])
        fails.append("duplicate edge_id did not raise")
    except ValueError:
        pass

    # 3. concurrent same-identity sessions: source_logon_id keeps them distinct
    def _e(eid, src, dst, ident, lid, slid=None, priv="absent", t="10:00:00"):
        return {"edge_id": eid, "@timestamp": f"2026-08-10T{t}Z", "source_host": src, "target_host": dst,
                "identity": ident, "effective_identity": ident, "service": "rdp", "logon_id": lid,
                "source_logon_id": slid, "privilege_state": priv, "auth_state": "confirmed",
                "credential_transition": None, "evidence_refs": {"network": "n", "logon": "l",
                "privilege": "p" if priv == "confirmed" else None}}
    recs = [_e("s1", "WS-ENG-12", "SRV-APP-01", ALICE, "0xL1", priv="confirmed"),          # priv session L1
            _e("s2", "WS-ENG-12", "SRV-APP-01", ALICE, "0xL2", priv="absent", t="10:00:05"), # ordinary L2
            _e("s3", "SRV-APP-01", "SRV-FILE-02", ALICE, "0xL9", slid="0xL1", t="10:05:00")]  # from L1
    fs = classify(ReachabilityGraph.from_records(recs), load_context())
    prog = [f for f in fs if f["path"] == ["WS-ENG-12", "SRV-APP-01", "SRV-FILE-02"]]
    if len(prog) != 1 or prog[0]["modifiers"].get("session_lineage") != "session-exact":
        fails.append(f"concurrent-session lineage wrong: {[(p['label'], p['modifiers'].get('session_lineage')) for p in prog]}")

    if fails:
        print("[FAIL] edge contract")
        for f in fails:
            print(f"       - {f}")
        return 1
    print("[PASS] edge contract: forged identity coerced, duplicate edge_id rejected, session lineage exact")
    return 0


if __name__ == "__main__":
    sys.exit(main())
