# Detection Engineering Portfolio

A Detections-as-Code portfolio built on the Elastic Stack. Each detection is a
self-contained, version-controlled, and CI-tested unit that pairs the query
logic with its hypothesis, MITRE ATT&CK mapping, and validation data.

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

GitHub Actions validates every detection on pushes and pull requests to
`main`. Each successful run also publishes a downloadable
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
- **Falsifiable** — every detection ships with both a true-positive and a false-positive sample.

---

## Author

Désiré Abdoul Kader BONZI  — MSc Cybersecurity
Research: identity reachability and lateral movement detection.
