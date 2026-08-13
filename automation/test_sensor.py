#!/usr/bin/env python3
"""Test the ECS sensor against its pcap fixtures.

Runs the sensor in pcap-replay mode (no privileges) over each fixture and asserts
the emitted ECS network events match what the scenario should produce. This makes
the sensor's behaviour part of CI, exactly like the detection logic tests.

Exits non-zero on any failure.
"""
from __future__ import annotations

import io
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SENSOR_DIR = REPO_ROOT / "sensor"
FIXTURES = SENSOR_DIR / "fixtures"

sys.path.insert(0, str(SENSOR_DIR))
import json  # noqa: E402

import sensor as sensor_mod  # noqa: E402
from scapy.all import rdpcap  # noqa: E402


def _run_sensor(pcap: pathlib.Path, host="test-host") -> list[dict]:
    buf = io.StringIO()
    sensor_mod.run(rdpcap(str(pcap)), host, buf)
    return [json.loads(line) for line in buf.getvalue().splitlines() if line.strip()]


def _check(name: str, cond: bool, detail: str, failures: list[str]) -> None:
    if not cond:
        failures.append(f"{name}: {detail}")


def test_lateral_movement(failures: list[str]) -> None:
    evs = _run_sensor(FIXTURES / "lateral_movement.pcap")
    rdp = [e for e in evs if e["destination"]["port"] == 3389]
    _check("lateral_movement", len(rdp) == 1, f"expected 1 RDP flow, got {len(rdp)}", failures)
    if rdp:
        e = rdp[0]
        _check("lateral_movement", e["network"]["protocol"] == "rdp",
               f"expected protocol rdp, got {e['network']['protocol']}", failures)
        _check("lateral_movement", e["network"]["transport"] == "tcp",
               "expected tcp transport", failures)
        _check("lateral_movement", "network" in e["event"]["category"],
               "expected event.category to include 'network'", failures)


def test_port_scan(failures: list[str]) -> None:
    evs = _run_sensor(FIXTURES / "port_scan.pcap")
    ports = {e["destination"]["port"] for e in evs
             if e["source"]["ip"] == "10.20.9.99" and e["destination"]["ip"] == "10.20.4.60"}
    _check("port_scan", len(ports) >= 15,
           f"expected >=15 distinct dst ports from scanner, got {len(ports)}", failures)


def test_benign(failures: list[str]) -> None:
    evs = _run_sensor(FIXTURES / "benign.pcap")
    # No single (src,dst) pair should fan out across many ports.
    from collections import defaultdict
    pairs = defaultdict(set)
    for e in evs:
        pairs[(e["source"]["ip"], e["destination"]["ip"])].add(e["destination"]["port"])
    worst = max((len(p) for p in pairs.values()), default=0)
    _check("benign", worst < 15, f"benign traffic fanned out to {worst} ports", failures)


def main() -> int:
    if not FIXTURES.exists() or not any(FIXTURES.glob("*.pcap")):
        print("No fixtures found. Run: python sensor/generate_fixtures.py")
        return 1

    failures: list[str] = []
    for fn in (test_lateral_movement, test_port_scan, test_benign):
        fn(failures)

    if failures:
        print(f"[FAIL] sensor ({len(failures)} check(s))")
        for f in failures:
            print(f"       - {f}")
        return 1
    print("[PASS] sensor: lateral_movement, port_scan, benign fixtures all as expected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
