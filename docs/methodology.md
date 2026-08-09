# Methodology

## The detection unit

Every detection lives in its own folder under `detections/` and is treated as a
self-contained unit of work. A unit is only "done" when it answers four
questions, in order:

1. **Hypothesis** — what adversary behaviour are we trying to catch, and why is
   this signal higher-fidelity than the obvious naive version? (`README.md`)
2. **Query** — the detection logic itself. (`query.eql`, wrapped in `rule.toml`)
3. **Validation** — a true-positive sample that should fire and a false-positive
   sample that should not. (`test_data/`)
4. **ATT&CK mapping** — where this sits in the adversary model. (`metadata.yml`)

This structure is deliberate: it forces each detection to be *falsifiable* and
*traceable*, not just a clever query.

## Query language choice

- **EQL** is the primary language for signature detections, because lateral
  movement is a sequence problem — "A happened, then B, by the same identity."
  EQL's `sequence ... by` construct expresses that directly.
- **ES|QL** is used for aggregation- or threshold-style detections (bursts, rare
  combinations) and to demonstrate range with Elastic's newest language.
- **KQL / Lucene** are reserved for single-event custom-query rules where no
  correlation is needed.

## Detections-as-Code

Rules are text files under version control. Every push runs
`automation/validate_rules.py` in CI, so a malformed rule or a broken ATT&CK
mapping fails the build before it is merged. This mirrors how a mature SOC
manages detection content and keeps the portfolio honest.

## Data hygiene

All events under `test_data/` are synthetic. No production logs, real IP
addresses, hostnames, or account names appear anywhere in this repository.
