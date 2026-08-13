#!/usr/bin/env python3
"""ECS network telemetry sensor.

Captures (or replays) packets with Scapy, aggregates them into flows, and emits
Elastic Common Schema (ECS) network events as NDJSON — one event per flow. The
sensor is a *telemetry producer only*: it does not decide what is malicious.
Correlation and detection live in the detection rules under ../detections, which
join these network events with Windows authentication and process events.

Modes:
  --pcap FILE     replay a capture file (no privileges needed; used in CI/tests)
  --iface IFACE   live capture (requires root/Administrator for raw sockets)

Output:
  --out FILE      write NDJSON here (default: stdout)

Example:
  python sensor/sensor.py --pcap sensor/fixtures/lateral_movement.pcap
  sudo python sensor/sensor.py --iface eth0 --out network.ndjson
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import dataclass, field

logging.getLogger("scapy").setLevel(logging.ERROR)
from scapy.all import IP, TCP, UDP, rdpcap, sniff  # noqa: E402

# Minimal, extensible port -> application protocol map (best-effort labelling).
PORT_PROTO = {
    3389: "rdp", 445: "smb", 139: "netbios-ssn", 88: "kerberos",
    53: "dns", 80: "http", 443: "https", 389: "ldap", 636: "ldaps",
    135: "msrpc", 5985: "winrm", 5986: "winrm",
}


@dataclass
class Flow:
    src_ip: str
    dst_ip: str
    transport: str
    dst_port: int
    src_port: int
    first: float
    last: float
    packets: int = 0
    bytes: int = 0
    flags: set = field(default_factory=set)

    def key(self):
        return (self.src_ip, self.dst_ip, self.transport, self.dst_port)


def _flow_key(pkt):
    if IP not in pkt:
        return None
    ip = pkt[IP]
    if TCP in pkt:
        l4, transport = pkt[TCP], "tcp"
    elif UDP in pkt:
        l4, transport = pkt[UDP], "udp"
    else:
        return None
    return (ip.src, ip.dst, transport, int(l4.dport), int(l4.sport), l4)


def aggregate(packets) -> list[Flow]:
    """Collapse packets into flows keyed by (src, dst, transport, dst_port)."""
    flows: dict[tuple, Flow] = {}
    for pkt in packets:
        parsed = _flow_key(pkt)
        if parsed is None:
            continue
        src, dst, transport, dport, sport, l4 = parsed
        t = float(getattr(pkt, "time", 0.0))
        k = (src, dst, transport, dport)
        f = flows.get(k)
        if f is None:
            f = Flow(src, dst, transport, dport, sport, first=t, last=t)
            flows[k] = f
        f.packets += 1
        f.bytes += len(bytes(pkt))
        f.first = min(f.first, t)
        f.last = max(f.last, t)
        if transport == "tcp":
            f.flags.update(str(l4.flags))
    return list(flows.values())


def to_ecs(flow: Flow, host_name: str) -> dict:
    """Render a Flow as an ECS network event (dict, ready for JSON serialisation)."""
    from datetime import datetime, timezone
    ts = datetime.fromtimestamp(flow.first, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "@timestamp": ts,
        "event": {
            "category": ["network"],
            "type": ["connection"],
            "action": "network_flow",
            "duration": int(max(0.0, flow.last - flow.first) * 1_000_000_000),  # ns
        },
        "source": {"ip": flow.src_ip, "port": flow.src_port},
        "destination": {"ip": flow.dst_ip, "port": flow.dst_port},
        "network": {
            "transport": flow.transport,
            "protocol": PORT_PROTO.get(flow.dst_port),
            "packets": flow.packets,
            "bytes": flow.bytes,
        },
        "host": {"name": host_name},
        "observer": {"type": "scapy-ecs-sensor"},
    }


def run(packets, host_name: str, out) -> int:
    flows = aggregate(packets)
    # Deterministic ordering: by start time, then destination port.
    flows.sort(key=lambda f: (f.first, f.dst_port))
    for flow in flows:
        out.write(json.dumps(to_ecs(flow, host_name)) + "\n")
    return len(flows)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="ECS network telemetry sensor")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--pcap", help="replay a capture file (no privileges needed)")
    src.add_argument("--iface", help="live capture interface (requires root)")
    ap.add_argument("--out", help="output NDJSON file (default: stdout)")
    ap.add_argument("--host-name", default="sensor-host", help="host.name to stamp on events")
    ap.add_argument("--count", type=int, default=0, help="live mode: stop after N packets (0 = until Ctrl-C)")
    args = ap.parse_args(argv)

    if args.pcap:
        packets = rdpcap(args.pcap)
    else:
        packets = sniff(iface=args.iface, count=args.count or 0)

    out = open(args.out, "w", encoding="utf-8") if args.out else sys.stdout
    try:
        n = run(packets, args.host_name, out)
    finally:
        if args.out:
            out.close()
    print(f"emitted {n} ECS network event(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
