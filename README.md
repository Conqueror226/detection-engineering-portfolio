# Detection Engineering Portfolio

A Detections-as-Code portfolio built on the Elastic Stack. Each detection is a
self-contained, version-controlled unit that pairs the query logic with its
hypothesis, MITRE ATT&CK mapping, and validation data. On every push, CI checks
each unit's structure and, for EQL rules, executes the query against its samples
(see the CI section for exactly what is and isn't covered).

The focus is **identity-based lateral movement detection** (my research niche),
complemented by a set of widely-recognised "classic" detections to demonstrate
range.

---

## Repository layout

```
detection-engineering-portfolio/
├── detections/                 # one folder per detection (the "detection unit")
│   └── <TECHNIQUE>_<name>/
│       ├── rule.toml           # Elastic detection rule (Detections-as-Code)
│       ├── query.eql           # the detection logic
│       ├── metadata.yml        # ATT&CK mapping, data sources, references
│       ├── test_data/          # sample events: true & false positives
│       └── README.md           # hypothesis, logic, tuning notes
├── automation/                 # Python tooling (validation, coverage, Navigator)
├── attack_navigator/           # generated ATT&CK Navigator coverage layer
├── docs/                       # methodology and design notes
└── .github/workflows/          # CI that validates every rule on push
```

Every detection answers four questions in order:
**hypothesis → query → validation → ATT&CK mapping.**

---

## Coverage matrix

| Detection | Technique | Tactic | Language | Category | Status |
|---|---|---|---|---|---|
| RDP Lateral Movement → Process Execution | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Lateral Movement | EQL | signature | development |
| Anomalous RC4 Kerberos TGT (Overpass-the-Hash) | [T1550.002](https://attack.mitre.org/techniques/T1550/002/) | Lateral Movement | EQL | signature | development |
| PowerShell Encoded Command Execution | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Execution | ES\|QL | classic | development |

_Signature = my research niche. Classic = recruiter-legible baseline detections._

Regenerate the coverage view and ATT&CK Navigator layer from metadata:

```bash
python automation/coverage_report.py
python automation/generate_navigator_layer.py
```

### CI artifacts

On every push and pull request to `main`, GitHub Actions runs two checks:

1. **Structure validation** (`validate_rules.py`) — required fields exist,
   referenced files are present, ATT&CK IDs are well-formed, and each detection
   ships a true- and false-positive sample.
2. **Logic tests** (`test_detections.py`) — for every **EQL** detection, the query
   is executed against its samples with Elastic's `eql` engine and asserted to
   fire on the true-positive and stay silent on the false-positive; sequence rules
   are timed so `maxspan` is genuinely enforced. **ES|QL** detections have no
   offline engine, so they are structure-validated only and reported as skipped.

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
- **Falsifiable** — every detection ships a true-positive and a false-positive sample. For EQL detections CI executes the query against both and asserts the expected outcome; ES|QL samples are validated against a live stack.

---

## Author

Désiré Abdoul Kader Bonzi — MSc Cybersecurity, Ritsumeikan University.
Research: identity reachability and lateral movement detection.
