# Network Service Discovery via Port Fan-Out

**Technique:** [T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046/)
**Tactic:** Discovery (TA0007)
**Language:** ES|QL (aggregation) · **Category:** classic · **Status:** development

---

## Hypothesis

A port scan has a shape that ordinary traffic doesn't: **one source, one target,
many distinct destination ports, short window**. A legitimate client opens one or
two services on a host; a scanner fans out across dozens. Aggregating the Scapy
sensor's flow events and counting distinct destination ports per
`(source, destination)` surfaces exactly that fan-out.

Analogy: one person trying every door in the building, one after another, isn't
visiting — they're casing it.

## Logic

An ES|QL aggregation over the sensor's network events:

1. Filter to TCP network events.
2. `STATS COUNT_DISTINCT(destination.port) BY source.ip, destination.ip`.
3. Keep pairs where the distinct-port count crosses the threshold (`>= 15`).

`COUNT_DISTINCT` is why this is ES|QL and not EQL — EQL has no distinct-count
threshold. Note: `_id` is **not** preserved through `STATS` (aggregate result rows
become alerts), so it provides no source-document deduplication here. The rule's
`from = "now-10m"` gives a rolling ten-minute window; use alert suppression on
`source.ip`/`destination.ip` if repeated aggregate alerts are noisy.

## Data source

- Scapy ECS network sensor (`../../sensor`), `event.category "network"`

## Validation

The samples here are the **sensor's real output** on the fixtures
(`sensor/fixtures/`), not hand-written:

| File | Source fixture | Expectation |
|---|---|---|
| `test_data/true_positive.json` | `port_scan.pcap` | one src → 25 distinct ports → fires (>= 15) |
| `test_data/false_positive.json` | `benign.pcap` | max 1 distinct port per pair → no fire |

Because ES|QL has no offline engine, the CI logic harness reports this detection
as **skipped**; the fan-out logic is checked against these samples during
development. It is **not executed in CI** and should be validated on a live
Elastic stack before production use.

## Tuning notes

- **Threshold is environment-specific.** 15 is a starting point; raise it where
  monitoring tools legitimately probe many ports.
- Allowlist sanctioned scanners (Nessus, OpenVAS) and asset-management ranges by
  `source.ip`.
- Add a time-bucket (`BY source.ip, destination.ip, bucket(@timestamp, 1 minute)`)
  in a live deployment so the fan-out is measured per window, not across all time.
