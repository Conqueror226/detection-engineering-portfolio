#!/usr/bin/env python3
"""ECS network telemetry sensor (bidirectional flows).

Captures or replays packets, folds both directions of a conversation into one
canonical flow (client = the SYN initiator; server = the listener), and emits ECS
network events as NDJSON. Client/server orientation means an ephemeral return
flow can never masquerade as a new connection to a high port — which is what kept
T1046 honest. Sensor identity lives under `observer.*`, not `host.*`.

Modes:
  --pcap FILE     replay a capture (no privileges; used in CI/tests)
  --iface IFACE   live capture via AsyncSniffer with periodic flow flushing
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

logging.getLogger("scapy").setLevel(logging.ERROR)
# File replay must remain usable in restricted/offline CI environments where
# interface discovery and route-table netlink sockets are intentionally blocked.
# Live capture still works when an explicit --iface is supplied on a normal host.
from scapy.config import conf  # noqa: E402
from scapy.interfaces import NetworkInterfaceDict  # noqa: E402

conf.route_autoload = False
conf.route6_autoload = False
_original_reload = NetworkInterfaceDict.reload


def _permission_safe_reload(self):
    try:
        return _original_reload(self)
    except PermissionError:
        self.clear()
        return None


NetworkInterfaceDict.reload = _permission_safe_reload
from scapy.all import IP, TCP, UDP, AsyncSniffer, PcapReader, rdpcap  # noqa: E402

ECS_VERSION = "8.11.0"
PORT_PROTO = {
    3389: "rdp", 445: "smb", 139: "netbios-ssn", 88: "kerberos", 53: "dns",
    80: "http", 443: "https", 389: "ldap", 636: "ldaps", 135: "msrpc",
    5985: "winrm", 5986: "winrm",
}


def _canonical(ip_a, pa, ip_b, pb, transport):
    """Direction-independent flow key."""
    return tuple(sorted([(ip_a, pa), (ip_b, pb)])) + (transport,)


@dataclass
class Flow:
    ep1: tuple            # (ip, port)
    ep2: tuple
    transport: str
    first: float
    last: float
    # orientation
    client: tuple | None = None   # (ip, port) of SYN initiator
    server: tuple | None = None
    # directional counters keyed by source endpoint
    pkts: dict = field(default_factory=dict)
    bytez: dict = field(default_factory=dict)
    saw_syn: bool = False

    def add(self, src_ep, dst_ep, size, t, flags):
        self.first = min(self.first, t); self.last = max(self.last, t)
        self.pkts[src_ep] = self.pkts.get(src_ep, 0) + 1
        self.bytez[src_ep] = self.bytez.get(src_ep, 0) + size
        if flags is not None and not self.saw_syn:
            s = "S" in flags and "A" not in flags
            sa = "S" in flags and "A" in flags
            if s:
                self.client, self.server, self.saw_syn = src_ep, dst_ep, True
            elif sa:
                self.client, self.server, self.saw_syn = dst_ep, src_ep, True
        if self.client is None:            # fallback: first-seen src is client
            self.client, self.server = src_ep, dst_ep


def _parse(pkt):
    if IP not in pkt:
        return None
    ip = pkt[IP]
    if TCP in pkt:
        l4, transport, flags = pkt[TCP], "tcp", str(pkt[TCP].flags)
    elif UDP in pkt:
        l4, transport, flags = pkt[UDP], "udp", None
    else:
        return None
    return (ip.src, int(l4.sport)), (ip.dst, int(l4.dport)), transport, flags, len(bytes(pkt)), \
        float(getattr(pkt, "time", 0.0))


def aggregate(packets) -> list[Flow]:
    flows: dict[tuple, Flow] = {}
    for pkt in packets:
        p = _parse(pkt)
        if p is None:
            continue
        src_ep, dst_ep, transport, flags, size, t = p
        k = _canonical(*src_ep, *dst_ep, transport)
        f = flows.get(k)
        if f is None:
            f = Flow(ep1=src_ep, ep2=dst_ep, transport=transport, first=t, last=t)
            flows[k] = f
        f.add(src_ep, dst_ep, size, t, flags)
    return list(flows.values())


def to_ecs(flow: Flow, observer_hostname: str) -> dict:
    client, server = flow.client, flow.server
    ts = datetime.fromtimestamp(flow.first, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    c_pkts, c_bytes = flow.pkts.get(client, 0), flow.bytez.get(client, 0)
    s_pkts, s_bytes = flow.pkts.get(server, 0), flow.bytez.get(server, 0)
    return {
        "@timestamp": ts,
        "ecs": {"version": ECS_VERSION},
        "event": {
            "kind": "event", "category": ["network"], "type": ["connection"],
            "action": "network_flow", "module": "network_flow", "dataset": "network_flow.flow",
            "duration": int(max(0.0, flow.last - flow.first) * 1_000_000_000),
        },
        "observer": {"hostname": observer_hostname, "type": "sensor",
                     "product": "scapy-ecs-sensor", "vendor": "portfolio"},
        "client": {"ip": client[0], "port": client[1], "packets": c_pkts, "bytes": c_bytes},
        "server": {"ip": server[0], "port": server[1], "packets": s_pkts, "bytes": s_bytes},
        # source = client, destination = server (orientation-stable for consumers)
        "source": {"ip": client[0], "port": client[1], "packets": c_pkts, "bytes": c_bytes},
        "destination": {"ip": server[0], "port": server[1], "packets": s_pkts, "bytes": s_bytes},
        "network": {
            "transport": flow.transport, "protocol": PORT_PROTO.get(server[1]),
            "packets": c_pkts + s_pkts, "bytes": c_bytes + s_bytes,
            "direction": "unknown",
        },
    }


def run(packets, observer_hostname: str, out) -> int:
    flows = aggregate(packets)
    flows.sort(key=lambda f: (f.first, (f.server or f.ep2)[1]))
    for flow in flows:
        out.write(json.dumps(to_ecs(flow, observer_hostname)) + "\n")
    return len(flows)


def live_sniff(iface: str, observer_hostname: str, out, flush_interval: int = 30,
               idle_timeout: int = 60, stop_after: float | None = None) -> None:
    """Real-time capture: AsyncSniffer feeds a shared flow table; a timer thread
    periodically flushes flows idle beyond `idle_timeout` so events stream out
    instead of only appearing at capture end."""
    flows: dict[tuple, Flow] = {}
    lock = threading.Lock()

    def _on(pkt):
        p = _parse(pkt)
        if p is None:
            return
        src_ep, dst_ep, transport, flags, size, t = p
        k = _canonical(*src_ep, *dst_ep, transport)
        with lock:
            f = flows.get(k) or Flow(ep1=src_ep, ep2=dst_ep, transport=transport, first=t, last=t)
            flows[k] = f
            f.add(src_ep, dst_ep, size, t, flags)

    def _flush(final=False):
        now = time.time()
        with lock:
            due = [k for k, f in flows.items() if final or (now - f.last) >= idle_timeout]
            for k in due:
                out.write(json.dumps(to_ecs(flows.pop(k), observer_hostname)) + "\n")
            out.flush()

    sniffer = AsyncSniffer(iface=iface, store=False, prn=_on)
    sniffer.start()
    start = time.time()
    try:
        while True:
            time.sleep(flush_interval)
            _flush()
            if stop_after and (time.time() - start) >= stop_after:
                break
    except KeyboardInterrupt:
        pass
    finally:
        sniffer.stop()
        _flush(final=True)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="ECS network telemetry sensor")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--pcap")
    src.add_argument("--iface")
    ap.add_argument("--out")
    ap.add_argument("--observer-hostname", default="sensor-host")
    ap.add_argument("--flush-interval", type=int, default=30)
    args = ap.parse_args(argv)
    out = open(args.out, "w", encoding="utf-8") if args.out else sys.stdout
    try:
        if args.pcap:
            n = run(rdpcap(args.pcap), args.observer_hostname, out)
            print(f"emitted {n} ECS network event(s)", file=sys.stderr)
        else:
            live_sniff(args.iface, args.observer_hostname, out, args.flush_interval)
    finally:
        if args.out:
            out.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
