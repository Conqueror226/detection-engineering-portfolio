# Authenticated Pivot: Network Connection → Auth → Process Execution

**Technique:** [T1021.001 — Remote Services: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/)
**Tactic:** Lateral Movement (TA0008)
**Language:** EQL (sequence, 3 data sources) · **Category:** signature · **Status:** development

---

> **Role:** this is *edge establishment* — it confirms a pivot occurred. Multi-hop
> progression and the administrative blind spot are handled by the privileged pivot
> progression unit (`../T1021_privileged_pivot_progression`), which chains edges
> across hosts with tier/role context.

## Hypothesis

Lateral movement leaves a trail across three layers, and the fidelity is in their
*combination*:

1. **Network** — an east-west connection to a remote-access service (RDP 3389 / SMB 445).
2. **Identity** — a successful logon on the target (4624, LogonType 10 or 3).
3. **Endpoint** — process execution by that identity after the logon.

The network layer establishes that *the edge exists* — who reached whom, over what
service, when. It does **not** by itself prove the edge was traversed maliciously;
that's what the host and identity evidence add. This detection is the portfolio's
correlation piece: it joins the Scapy sensor's network telemetry to Windows auth
and process events rather than treating packets as standalone proof.

Analogy: the network sensor is the building's door-badge log (someone opened this
door at 10:00), the auth event is the sign-in sheet (it was Tanaka), and the
process event is the work order they filed inside. Any one is thin; all three,
in order, on the same floor, is a story.

## Logic

An EQL **sequence** with `maxspan=5m`, joined on the **target host**
(network `destination.ip` == auth/process `host.ip`):

1. `network` — tcp, `destination.port in (3389, 445)`, `network.protocol in ("rdp","smb")`
2. `authentication` — `4624`, `event.outcome == "success"`, `LogonType in ("10","3")`
3. `process` — `event.type == "start"`

## Data sources

- **Network:** ECS events from the Scapy sensor (`../../sensor`)
- Windows Security Event Log — 4624
- Sysmon Event ID 1 / `process.start`

## Validation

| File | Expectation |
|---|---|
| `test_data/true_positive.json` | RDP flow → 4624 → process, same target, within 5m → fires |
| `test_data/false_positive.json` | (a) benign-port connection; (b) process on a different host → no fire |

## Tuning notes

- **IP ↔ host enrichment is a prerequisite.** The join assumes `destination.ip`
  (network) resolves to the same asset as `host.ip` (auth/process). Without an
  asset inventory or enrichment pipeline, the join won't hold in production.
- Allowlist jump hosts, bastions, and automation identities.
- This is corroboration, not attribution: a fired alert says *a connection, a
  logon, and execution lined up* — investigate, don't auto-block.
- Naturally extends detection #1 (auth → process) by prepending the network edge.
