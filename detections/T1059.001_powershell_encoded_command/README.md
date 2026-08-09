# PowerShell Encoded Command Execution

**Technique:** [T1059.001 — Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
**Tactic:** Execution (TA0002)
**Language:** ES|QL · **Category:** classic · **Status:** development

---

## Hypothesis

Base64-encoding a PowerShell command (`-EncodedCommand` / `-enc`) is a routine
way for attackers to hide a payload from casual inspection and simple string
matching. Legitimate encoded use exists, but it is uncommon enough that every
instance is worth a look. This is a widely-recognised "classic" detection that
recruiters expect to see — it demonstrates breadth beyond the identity niche.

Analogy: it's not the letter that's suspicious, it's that someone bothered to
write it in cipher. Encoding isn't proof of malice, but it's a reason to open the
envelope.

## Logic

An ES|QL pipeline:

1. `FROM` process indices, filter to process-start events.
2. Lower-case `process.name` and `process.command_line` for case-insensitive matching.
3. Keep only `powershell.exe` / `pwsh.exe`.
4. `RLIKE` matches the encoded-command flag family: `-e`, `-enc`, `-encodedcommand`.
5. `KEEP` the useful fields and `SORT` newest first for triage.

This is the portfolio's first **ES|QL** rule. EQL handles the sequence-based
identity detections; ES|QL's piped, aggregation-friendly syntax fits single-event
and analytics-style detections and shows a second Elastic query language.

## Data source

- Sysmon Event ID 1 / `process.start`

## Validation

| File | Expectation |
|---|---|
| `test_data/true_positive.json` | `powershell.exe -enc <base64>` → rule should fire |
| `test_data/false_positive.json` | Normal PowerShell + a non-PowerShell process → rule should not fire |

## Tuning notes

- Baseline legitimate encoders (deployment tooling, EDR agents) and allowlist them.
- Consider enriching with the **decoded** command in a follow-up analytic; the
  decoded content is where true intent shows.
- Watch for obfuscation that splits or cases the flag unusually; the lower-casing
  step handles case, but heavy obfuscation may need a dedicated rule.
