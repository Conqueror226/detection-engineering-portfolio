# PowerShell Encoded Command Execution

**Technique:** [T1059.001 — Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
**Tactic:** Execution (TA0002)
**Language:** ES|QL · **Category:** classic · **Status:** development

---

## Hypothesis

Base64-encoding a PowerShell command (`-EncodedCommand` / `-enc`) is a routine
way to hide a payload from casual inspection and simple string matching.
Legitimate encoded use exists, so this is a review-worthy signal rather than a
high-confidence one — worth catching precisely, with the noise controlled.

Analogy: it's not the letter that's suspicious, it's that someone bothered to
write it in cipher *and* the message is long. Encoding isn't proof of malice, but
an encoded blob is a reason to open the envelope.

## Logic

An ES|QL pipeline:

1. `FROM … METADATA _id, _version, _index` — carry the source `_id` so the
   detection engine can deduplicate alerts (required for non-aggregating ES|QL
   rules; dropping `_id` in `KEEP` breaks dedup).
2. Filter to process-start events.
3. Lower-case `process.name` and `process.command_line` for case-insensitive matching.
4. Keep only `powershell.exe` / `pwsh.exe`.
5. `RLIKE` matches the **full** encoded-command prefix family — `-e`, `-en`,
   `-enc`, `-enco`, … through `-encodedcommand` — using a nested-optional pattern,
   and requires a following Base64-looking token of 20+ chars. The payload
   requirement is what removes the noisy bare-`-e` false positives.
6. `KEEP` the useful fields (including `_id`) and `SORT` newest first for triage.

This is the portfolio's first **ES|QL** rule. EQL handles the sequence-based
identity detections; ES|QL's piped syntax fits single-event and analytics-style
detections and shows a second Elastic query language.

## Data source

- Sysmon Event ID 1 / `process.start`

## Validation

| File | Expectation |
|---|---|
| `test_data/true_positive.json` | `powershell.exe … -encod <long base64>` → rule should fire |
| `test_data/false_positive.json` | Normal PowerShell + a non-PowerShell process → rule should not fire |

The true-positive deliberately uses a mid-prefix flag (`-encod`) to exercise the
full prefix coverage, not just `-enc`.

## Tuning notes

- Baseline legitimate encoders (deployment tooling, EDR agents) and allowlist them.
- Enrich with the **decoded** command in a follow-up analytic; the decoded content
  is where true intent shows.
- The 20-char Base64 floor is a heuristic — real payloads are far longer. Lower it
  only if you see short-but-malicious encodings in your environment.
