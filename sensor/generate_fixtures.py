#!/usr/bin/env python3
"""Generate reproducible synthetic pcap fixtures for the sensor tests.

No real capture is used. Each pcap encodes a specific, documented scenario so the
sensor's ECS output is deterministic and the detection tests are meaningful.

Run:  python3 sensor/generate_fixtures.py
Writes: sensor/fixtures/{lateral_movement,port_scan,benign}.pcap
"""
from __future__ import annotations

import logging
import pathlib

logging.getLogger("scapy").setLevel(logging.ERROR)
from scapy.all import IP, TCP, UDP, Ether, wrpcap  # noqa: E402

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"

ATTACKER = "10.20.4.51"
TARGET = "10.20.4.60"
SCANNER = "10.20.9.99"
BASE_T = 1_754_820_000.0  # fixed epoch base for deterministic timestamps


def _pkt(src, dst, sport, dport, t, proto="tcp", flags="S", size=0):
    l3 = IP(src=src, dst=dst)
    l4 = TCP(sport=sport, dport=dport, flags=flags) if proto == "tcp" \
        else UDP(sport=sport, dport=dport)
    p = Ether() / l3 / l4
    if size:
        p = p / ("\x00" * size)
    p.time = t
    return p


def lateral_movement():
    """A single RDP (tcp/3389) connection: attacker -> target. The network edge
    of the 'network connection -> authenticated pivot -> process execution' story."""
    pkts = []
    sport = 49712
    # TCP handshake + a little data, all to 3389
    pkts.append(_pkt(ATTACKER, TARGET, sport, 3389, BASE_T + 0.00, flags="S"))
    pkts.append(_pkt(TARGET, ATTACKER, 3389, sport, BASE_T + 0.01, flags="SA"))
    pkts.append(_pkt(ATTACKER, TARGET, sport, 3389, BASE_T + 0.02, flags="A"))
    for i in range(4):
        pkts.append(_pkt(ATTACKER, TARGET, sport, 3389, BASE_T + 0.05 + i * 0.01,
                         flags="PA", size=120))
    return pkts


def port_scan():
    """One source touching many destination ports on one host in a short window:
    a vertical TCP SYN scan -> Network Service Discovery (T1046)."""
    pkts = []
    for i, dport in enumerate(range(20, 45)):  # 25 distinct ports
        pkts.append(_pkt(SCANNER, TARGET, 40000 + i, dport, BASE_T + i * 0.01, flags="S"))
    return pkts


def benign():
    """Ordinary traffic: an HTTPS flow and a DNS lookup. Should not look like
    lateral movement or a scan."""
    pkts = []
    pkts.append(_pkt(TARGET, "142.250.190.46", 51001, 443, BASE_T + 0.00, flags="S"))
    pkts.append(_pkt("142.250.190.46", TARGET, 443, 51001, BASE_T + 0.01, flags="SA"))
    for i in range(3):
        pkts.append(_pkt(TARGET, "142.250.190.46", 51001, 443, BASE_T + 0.03 + i * 0.01,
                         flags="PA", size=200))
    pkts.append(_pkt(TARGET, "192.168.1.1", 55000, 53, BASE_T + 0.10, proto="udp", size=40))
    return pkts


def https_fanout():
    """15 separate HTTPS connections from one client to ONE server (all server
    port 443). Many connections to a single service is NOT a port scan: distinct
    server ports = 1, so T1046 must not fire. Ephemeral client ports and the
    reverse direction must not inflate the distinct-destination-port count."""
    pkts = []
    for i in range(15):
        sport = 51000 + i
        pkts.append(_pkt(TARGET, "203.0.113.10", sport, 443, BASE_T + i * 0.1, flags="S"))
        pkts.append(_pkt("203.0.113.10", TARGET, 443, sport, BASE_T + i * 0.1 + 0.01, flags="SA"))
        pkts.append(_pkt(TARGET, "203.0.113.10", sport, 443, BASE_T + i * 0.1 + 0.02, flags="PA", size=180))
    return pkts


def main() -> int:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    for name, builder in (("lateral_movement", lateral_movement),
                          ("port_scan", port_scan),
                          ("benign", benign),
                          ("https_fanout", https_fanout)):
        out = FIXTURES / f"{name}.pcap"
        wrpcap(str(out), builder())
        print(f"wrote {out.relative_to(FIXTURES.parent.parent)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
