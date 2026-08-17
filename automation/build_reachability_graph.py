#!/usr/bin/env python3
"""Directed identity-reachability graph from PivotEdge records.

Correctness invariants enforced here (v7-review remediation):
  - effective_identity is TRUSTED only under a confirmed transition; with a null
    or unconfirmed transition it is coerced to `identity`, so a forged
    effective_identity cannot manufacture continuity.
  - duplicate edge_id values are rejected (a stable id must be unique).

Performance: two time-sorted, identity-aware indexes so only identity-compatible
candidates are examined, and pairs are streamed (not materialised) — the busy-hub
quadratic scan of the previous version is gone.
"""
from __future__ import annotations

import bisect
import datetime
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterator


def parse_ts(ts: str) -> datetime.datetime:
    dt = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def transition_is_confirmed(ct: dict | None) -> bool:
    return bool(ct and ct.get("state") == "confirmed"
               and ct.get("from_identity") and ct.get("to_identity"))


@dataclass
class Edge:
    edge_id: str
    timestamp: datetime.datetime
    source_host: str
    target_host: str
    identity: str
    effective_identity: str
    service: str | None = None
    logon_id: str | None = None
    source_logon_id: str | None = None
    privilege_state: str = "unknown"
    auth_state: str = "unknown"
    credential_transition: dict | None = None

    @property
    def is_privileged(self) -> bool:
        return self.privilege_state == "confirmed"

    @property
    def auth_confirmed(self) -> bool:
        return self.auth_state == "confirmed"

    @classmethod
    def from_record(cls, r: dict) -> "Edge":
        ct = r.get("credential_transition")
        # effective identity is trusted only under a confirmed transition.
        if transition_is_confirmed(ct):
            eff = ct["to_identity"]
        else:
            eff = r["identity"]
        return cls(
            edge_id=r["edge_id"], timestamp=parse_ts(r["@timestamp"]),
            source_host=r["source_host"], target_host=r["target_host"],
            identity=r["identity"], effective_identity=eff,
            service=r.get("service"), logon_id=r.get("logon_id"),
            source_logon_id=r.get("source_logon_id"),
            privilege_state=r.get("privilege_state", "unknown"),
            auth_state=r.get("auth_state", "unknown"),
            credential_transition=ct,
        )


def confirmed_transition_links(first: "Edge", nxt: "Edge") -> bool:
    """A confirmed transition whose endpoints match the two hops."""
    ct = nxt.credential_transition
    return bool(
        transition_is_confirmed(ct)
        and ct["from_identity"] == first.effective_identity
        and ct["to_identity"] == nxt.effective_identity
    )


def session_lineage(first: "Edge", nxt: "Edge") -> str:
    """'session-exact' when the outgoing edge's source session is the incoming
    edge's session; 'identity' when lineage is not derivable (no 4648/Sysmon)."""
    if nxt.source_logon_id is not None and first.logon_id is not None:
        return "session-exact" if nxt.source_logon_id == first.logon_id else "mismatch"
    return "identity"


@dataclass
class ReachabilityGraph:
    edges: list[Edge] = field(default_factory=list)

    @classmethod
    def from_records(cls, records: list[dict]) -> "ReachabilityGraph":
        seen: set[str] = set()
        for r in records:
            eid = r["edge_id"]
            if eid in seen:
                raise ValueError(f"duplicate edge_id: {eid!r}")
            seen.add(eid)
        edges = [Edge.from_record(r) for r in records]
        edges.sort(key=lambda e: e.timestamp)
        return cls(edges=edges)

    def _index(self):
        """Two identity-aware, time-sorted indexes keyed by the source host that a
        continuation would start from:
          direct[(host, identity)]      -> edges acting AS that identity from host
          transition[(host, from_id)]   -> edges whose confirmed transition comes FROM that identity
        """
        direct: dict[tuple, list[Edge]] = defaultdict(list)
        trans: dict[tuple, list[Edge]] = defaultdict(list)
        for e in self.edges:                       # already timestamp-sorted
            direct[(e.source_host, e.identity)].append(e)
            ct = e.credential_transition
            if transition_is_confirmed(ct):
                trans[(e.source_host, ct["from_identity"])].append(e)
        return direct, trans

    def iter_pairs(self, window_minutes: int = 30) -> Iterator[tuple[Edge, Edge]]:
        """Stream (first, nxt) continuation pairs, examining only identity-compatible
        candidates within the window."""
        direct, trans = self._index()
        ts_cache: dict[int, list] = {}
        win = window_minutes * 60

        def _emit(bucket, first):
            if not bucket:
                return
            key = id(bucket)
            tss = ts_cache.get(key)
            if tss is None:
                tss = [e.timestamp for e in bucket]
                ts_cache[key] = tss
            lo = bisect.bisect_right(tss, first.timestamp)
            for j in range(lo, len(bucket)):
                nxt = bucket[j]
                if (nxt.timestamp - first.timestamp).total_seconds() > win:
                    break
                if nxt.edge_id == first.edge_id:
                    continue
                # session-exact lineage: if the outgoing edge names its source
                # session, it must be THIS edge's session (defeats concurrent
                # same-identity sessions being conflated).
                if session_lineage(first, nxt) == "mismatch":
                    continue
                yield (first, nxt)

        for first in self.edges:
            k = (first.target_host, first.effective_identity)
            seen_ids: set[str] = set()
            for pair in _emit(direct.get(k), first):
                seen_ids.add(pair[1].edge_id)
                yield pair
            for pair in _emit(trans.get(k), first):
                if pair[1].edge_id not in seen_ids:      # avoid double-emitting
                    yield pair

    def build_index(self, window_minutes: int = 30):
        """Materialise pairs + second-hop ids (used by classify)."""
        pairs = list(self.iter_pairs(window_minutes))
        second_hop_ids = {n.edge_id for _, n in pairs}
        return pairs, second_hop_ids
