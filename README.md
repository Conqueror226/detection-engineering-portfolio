# Detection Engineering Portfolio

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
standalone proof.

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
│   ├── build_reachability_graph.py   # edges -> directed reachability graph
│   ├── classify_pivot_progression.py # progression classifier (admin blind-spot)
│   └── context/                      # tier/role/path/approval context (FIRE-style)
├── attack_navigator/           # generated ATT&CK Navigator coverage layer
├── docs/                       # methodology and design notes
└── .github/workflows/          # CI that validates every rule on push
```

Every detection answers four questions in order:
**hypothesis → query → validation → ATT&CK mapping.**

Architecture at a glance: [`docs/architecture.md`](docs/architecture.md) — the three
evidence layers (network → identity → endpoint) feeding the correlation rule.

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
python automation/coverage_report.py
python automation/generate_navigator_layer.py
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
git clone https://github.com/<your-username>/detection-engineering-portfolio.git
cd detection-engineering-portfolio
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# validate all detections
python automation/validate_rules.py
```

---

## Design principles

- **Detections-as-Code** — rules are text, versioned, reviewed, and tested like software.
- **No real data** — all `test_data/` events are synthetic. No production logs, IPs, or hostnames.
- **Traceable** — every detection maps to ATT&CK and cites its references.
- **Falsifiable** — every detection ships a true-positive and a false-positive sample. For EQL detections CI executes the query against both and asserts the expected outcome (including a `maxspan` timing case); ES|QL samples are not executed in CI and are provided for manual validation on a live stack.

---

## Author

Désiré Abdoul Kader Bonzi — MSc candidate (expected September 2026), Ritsumeikan University.
Research: identity reachability and lateral movement detection.
