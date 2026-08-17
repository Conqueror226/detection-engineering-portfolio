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

## Data hygiene and external validation

All committed events under `test_data/` are synthetic, so CI remains public,
deterministic, and free of production identifiers. Real EVTX, Elastic exports,
PCAPs, normalized evidence, and case reports are processed from git-ignored,
access-controlled paths by `automation/reconstruct_case.py`. The resulting
manifest records input/output SHA-256 values and parameters. Only aggregate,
reviewed validation results may be added to the repository; raw evidence stays in
controlled storage.

The manifest also hashes the five context files, records the exact code revision,
and exposes a stable `derivation_id`. The ID excludes runtime timestamps and
performance measurements, so identical evidence, context, parameters, code, and
derived outputs reproduce the same identifier. `generated_at_utc` and per-stage
milliseconds remain in the manifest as operational observations.

## Evidence-first automation

Automation removes manual pivot latency without replacing evidence discipline:

1. platform adapters normalize Windows/network and CloudTrail records;
2. deterministic joins establish only supported edges;
3. identity/session-aware indexes find compatible continuations;
4. three-state route policy returns authorized, prohibited, or unknown context;
5. reports retain evidence references, hashes, parameters, and limitations.

Machine learning is not used to assert edges, lineage, or authorization. An
optional ranking model may operate after classification, provided the underlying
finding and abstention state remain unchanged and visible.
