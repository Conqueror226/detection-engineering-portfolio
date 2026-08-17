# Detection Engineering Portfolio

**Detection-as-Code and evidence-based hybrid lateral-movement reconstruction
across Windows and AWS environments.**

A Detections-as-Code portfolio built on the Elastic Stack. Each detection is a
self-contained, version-controlled unit that pairs the query logic with its
hypothesis, MITRE ATT&CK mapping, and validation data. On every push, CI checks
each unit's structure and, for EQL rules, executes the query against its samples
(see the CI section for exactly what is and isn't covered).

The focus is **identity-based lateral movement detection** (my research niche),
complemented by widely-recognised "classic" detections for range. A Scapy-based
**ECS network sensor** adds a network-evidence layer, enabling a full-chain
signature: **network connection → authenticated pivot → process execution**.
Network telemetry corroborates host and identity evidence; it is never treated as
standalone proof. A platform-neutral `ReachabilityEdge` v2 adapter now places
these on-premises edges and successful AWS CloudTrail `sts:AssumeRole` events in
one evidence vocabulary without weakening either platform's native joins.

This repository is the broader detection-engineering portfolio. The proposed
DFRWS APAC workshop uses the forensic reconstruction component described below
as its working proof of concept.

## Forensic reconstruction proof of concept

**Workshop direction:** *Tracing the Unauthorized Path: Evidence-Based
Lateral-Movement Reconstruction*

The proof of concept reconstructs what route an identity actually used and
evaluates that observed route separately from the identity's entitlement. A
finding is emitted only when explicit artifact joins and active policy context
support it. Missing evidence produces `INSUFFICIENT_EVIDENCE`; incomplete policy
produces `INSUFFICIENT_CONTEXT` rather than an unsupported conclusion.

It demonstrates:

- strict network, host, authentication, logon-ID, and time joins for Windows
  pivot edges;
- a shared `ReachabilityEdge` v2 vocabulary for on-premises and AWS evidence;
- explicit, evidence-referenced identity mappings for cross-environment
  continuity;
- three-state route policy: `AUTHORIZED`, `PROHIBITED`, or `UNKNOWN_CONTEXT`;
- reproducible findings through evidence/context hashes, code revision,
  parameters, output hashes, and a stable `derivation_id`;
- measured offline pipeline stages without claiming real-time performance.

This is a **working proof of concept with a clearly defined scope**, not a
production forensic engine:

| Area | Currently implemented | Not claimed |
|---|---|---|
| On premises | PCAP plus Windows `4624`/`4672`/`4648`; RDP and SMB | Every protocol or Windows evidence source |
| AWS | Successful CloudTrail `sts:AssumeRole` | Every AWS service, workload event, or cloud provider |
| Progression | Evidence-supported two-hop Windows classification and hybrid v2 edge normalization | Arbitrary-length hybrid graph reasoning |
| Execution | Deterministic offline batch reconstruction with stage timings | Production-scale or real-time streaming deployment |

Start with [`docs/architecture.md`](docs/architecture.md),
[`docs/hybrid_reachability.md`](docs/hybrid_reachability.md), and
[`docs/real_evidence_workflow.md`](docs/real_evidence_workflow.md).

---

## Repository layout

```
detection-engineering-portfolio/
├── detections/                 # one folder per detection (the "detection unit")
│   └── <TECHNIQUE>_<name>/
│       ├── rule.toml           # Elastic detection rule (Detections-as-Code)
│       ├── query.eql|.esql     # the detection logic (EQL or ES|QL)
│       ├── metadata.yml        # ATT&CK mapping, data sources, references
│       ├── test_data/          # sample events: true & false positives
│       └── README.md           # hypothesis, logic, tuning notes
├── sensor/                     # Scapy -> ECS network telemetry sensor + pcap fixtures
├── automation/                 # Python tooling (validation, logic/sensor/progression tests, coverage)
│   ├── evidence_io.py               # EVTX/JSON/NDJSON/Elastic export normalization
│   ├── reconstruct_case.py           # offline evidence -> edges -> findings -> report
│   ├── hybrid_reachability.py         # PivotEdge v1 + CloudTrail -> ReachabilityEdge v2
│   ├── build_reachability_graph.py   # edges -> directed reachability graph
│   ├── classify_pivot_progression.py # progression classifier (admin blind-spot)
│   └── context/                      # tier/role/path/approval context (FIRE-style)
├── cases/                      # instructions only; real case evidence is git-ignored
├── attack_navigator/           # generated ATT&CK Navigator coverage layer
├── schemas/                    # v1 Windows + v2 hybrid evidence contracts
├── docs/                       # methodology and design notes
└── .github/workflows/          # CI that validates every rule on push
```

Every detection answers four questions in order:
**hypothesis → query → validation → ATT&CK mapping.**

Architecture at a glance: [`docs/architecture.md`](docs/architecture.md) —
platform-native evidence becomes evidence-supported edges, which are evaluated
against identity, session, and route-policy context.

---

## Coverage matrix

| Detection | Technique | Tactic | Language | Category | Status |
|---|---|---|---|---|---|
| RDP Lateral Movement → Process Execution | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Lateral Movement | EQL | signature | development |
| Anomalous RC4 Kerberos TGT Request (Potential Overpass-the-Hash) | [T1550.002](https://attack.mitre.org/techniques/T1550/002/) | Lateral Movement | EQL | signature | development |
| PowerShell Encoded Command Execution | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Execution | ES\|QL | classic | development |
| Authenticated Pivot: Connection → Auth → Process | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Lateral Movement | EQL | signature | development |
| Network Service Discovery via Port Fan-Out | [T1046](https://attack.mitre.org/techniques/T1046/) | Discovery | ES\|QL | classic | development |
| Privileged Pivot Progression (edge + graph) | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) · [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | Lateral Movement | EQL + Python | signature | development |

_Signature = my research niche. Classic = recruiter-legible baseline detections._

_Related behavior (not formal ATT&CK coverage): T1078.002 — valid domain credentials may enable the remote-service pivots. MITRE does not assign T1078 to Lateral Movement; it is cited as related evidence only._

Regenerate the coverage view and ATT&CK Navigator layer from metadata:

```bash
python3 automation/coverage_report.py
python3 automation/generate_navigator_layer.py
```

### CI artifacts

On every push and pull request to `main`, GitHub Actions runs the full gate set: contract + context validation (`validate_schemas.py`, `validate_context.py`), rule-structure validation, the EQL logic tests, the sensor tests, the edge-contract and materialization tests, the progression scenarios, and the end-to-end pipeline test (pcap → sensor → materializer → graph → finding):

1. **Structure validation** (`validate_rules.py`) — required fields exist,
   referenced files are present, ATT&CK IDs are well-formed, and each detection
   ships a true- and false-positive sample.
2. **Logic tests** (`test_detections.py`) — for every **EQL** detection, the query
   is executed against its samples with Elastic's `eql` engine and asserted to
   fire on the true-positive and stay silent on the false-positive. Sequence rules
   are timed: the RDP detection ships a false-positive whose two events are spaced
   beyond its `maxspan` (120s vs a 60s window), so the test fails if `maxspan` is
   not enforced. **ES|QL** detections have no offline engine and are **not
   executed in CI** — they are structure-validated only and reported as skipped;
   their samples are provided for manual validation on a live Elastic stack.
3. **Sensor tests** (`test_sensor.py`) — the Scapy ECS sensor is run in
   pcap-replay mode over its fixtures and its ECS output is asserted (RDP flow
   labelled, scan fan-out present, benign traffic flat). No privileges needed.
4. **Real-input, hybrid-adapter, and case-runner tests** (`test_evidence_io.py`,
   `test_hybrid_reachability.py`, `test_reconstruct_case.py`) — verify JSON,
   NDJSON, Elasticsearch exports, host-map enrichment, Windows-to-v2 lifting,
   CloudTrail AssumeRole materialization, evidence hashing, stable derivation
   IDs, performance measurements, output contracts, and the complete
   evidence-to-report workflow. Native EVTX uses the same adapter in operational
   runs; real evidence is deliberately not committed to CI.

Each successful run also publishes a downloadable
`detection-coverage-<run-number>` artifact containing:

- `coverage_report.txt` — human-readable coverage summary
- `coverage_layer.json` — ATT&CK Navigator layer

Download it from the workflow run's **Artifacts** section. To view the heatmap,
open [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/), choose
**Open Existing Layer**, and upload `coverage_layer.json`.

---

## Local setup

```bash
git clone https://github.com/Conqueror226/detection-engineering-portfolio.git
cd detection-engineering-portfolio
python3 -m venv .venv && source .venv/bin/activate
python3 -m pip install -r requirements.txt

# validate all detections
python3 automation/validate_rules.py
```

---

## Reconstruct a real lab case

The offline case runner accepts native Windows Security EVTX, ECS/Winlogbeat
JSON or NDJSON, Elasticsearch `_search` exports, and one or more real PCAPs. It
hashes every input, reports missing fields, preserves normalized evidence, and
produces contract-validated edges, findings, and a reconstruction report.

```bash
python3 automation/reconstruct_case.py \
  --case-name lab-rdp-pivot-01 \
  --pcap /secure-evidence/lab-rdp-pivot-01.pcap \
  --windows /secure-evidence/SRV-APP-01-Security.evtx \
  --windows /secure-evidence/DC01-Security.evtx \
  --cloudtrail /secure-evidence/cloudtrail-management-events.json \
  --ip-map /secure-evidence/ip_to_host.json \
  --out-dir /secure-results/lab-rdp-pivot-01
```

`--cloudtrail` is optional; when present, the same run also emits
`results/reachability_edges_v2.json` containing the lifted on-premises edges and
successful AWS `sts:AssumeRole` edges. The current Windows materializer is
currently limited to **RDP and SMB** and still
requires the strict network/authentication joins documented in
[`docs/architecture.md`](docs/architecture.md). See
[`docs/real_evidence_workflow.md`](docs/real_evidence_workflow.md) for authorized
collection, host mapping, clock checks, Elastic export shapes, and interpretation.

## Normalize on-premises and AWS evidence

`PivotEdge` v1 remains the frozen Windows-specific contract. The v2 adapter adds
a platform-neutral representation rather than breaking v1 consumers. It accepts
the v1 results above and/or CloudTrail JSON, NDJSON, or Elasticsearch exports:

```bash
python3 automation/hybrid_reachability.py \
  --pivot-edges /secure-results/lab-rdp-pivot-01/results/pivot_edges.json \
  --cloudtrail /secure-evidence/cloudtrail-management-events.json \
  --out /secure-results/lab-rdp-pivot-01/results/reachability_edges_v2.json \
  --quality-output /secure-results/lab-rdp-pivot-01/results/cloud_quality.json
```

The AWS adapter currently materializes successful `sts:AssumeRole` transitions.
Cross-environment continuity is confirmed only through an explicit,
evidence-referenced identity mapping; matching usernames, timestamps, or IPs do
not establish the bridge. See
[`docs/hybrid_reachability.md`](docs/hybrid_reachability.md).

## Automation, latency, and ML boundary

The core is deterministic and training-free: adapters normalize evidence, strict
joins materialize edges, an indexed graph composes compatible sessions, and
policy classifies the observed route. `manifest.json` records per-stage batch
runtime, every evidence and context hash, the code revision, and a stable
`derivation_id`. These are measurements of offline reconstruction latency, not a
real-time detection claim. Stateful streaming joins are a future deployment mode
for the same contracts.

Machine learning is intentionally outside the evidentiary core. It may rank
already materialized findings for analyst review, but it must not manufacture an
edge, confirm identity continuity, or turn missing policy into prohibition.

---

## Design principles

- **Detections-as-Code** — rules are text, versioned, reviewed, and tested like software.
- **No sensitive evidence in Git** — committed tests remain synthetic, while the
  offline runner processes real lab artifacts from external, git-ignored paths
  and records their SHA-256 provenance.
- **Traceable** — every detection maps to ATT&CK and cites its references.
- **Abstention-aware** — missing evidence yields `INSUFFICIENT_EVIDENCE`; policy
  outside a declared complete/active scope yields `INSUFFICIENT_CONTEXT`.
- **Falsifiable** — every detection ships a true-positive and a false-positive sample. For EQL detections CI executes the query against both and asserts the expected outcome (including a `maxspan` timing case); ES|QL samples are not executed in CI and are provided for manual validation on a live stack.

---

## Author

Désiré Abdoul Kader Bonzi — MSc candidate (expected September 2026), Ritsumeikan University.
Research: identity reachability and lateral movement detection.
