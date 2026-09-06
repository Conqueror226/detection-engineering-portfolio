# Research Purpose and Scope

## Purpose

This project investigates a practical way for small and medium-sized enterprises
(SMEs) and other resource-constrained security teams to reconstruct lateral
movement from evidence they can reasonably collect. It focuses on one forensic
question:

> Who reached which system, from where, through which observed route, and was
> that route authorized?

The method combines network observations, authentication records, cloud audit
events, and a small amount of organizational context. Its purpose is not only to
show that a privileged identity reached a critical asset, but also to distinguish
the identity's entitlement from the authorization of the route actually used.

## Research question

Can a resource-constrained organization reconstruct an observed identity path
and evaluate its route authorization using limited network and authentication
evidence, while avoiding conclusions that the available evidence cannot support?

## Intended users

The primary users are SME security practitioners, incident responders, and
managed-service analysts who may have limited staff, compute, training data, or
access to full system-level provenance. The workflow is also relevant to larger
organizations that need a small, inspectable reconstruction method for a bounded
case.

## Design requirements derived from the SME perspective

1. **Small evidence requirement.** Use commonly available network and
   authentication artifacts rather than requiring a complete enterprise data
   lake.
2. **Training-free core.** Do not require a machine-learning training set or a
   benign behavioral baseline to assert a forensic edge.
3. **Automation with inspectable rules.** Automate normalization, joins, graph
   construction, route-policy evaluation, and report generation while keeping
   every decision traceable to explicit rules.
4. **Honest uncertainty.** Return `INSUFFICIENT_EVIDENCE` when a session or
   credential transition is unsupported, and `INSUFFICIENT_CONTEXT` when policy
   is incomplete for the evaluated scope.
5. **Hybrid consistency.** Preserve platform-native evidence requirements while
   representing supported on-premises and cloud transitions in one shared edge
   vocabulary.
6. **Reproducibility.** Record input and context hashes, parameters, code
   revision, output hashes, and a stable derivation identifier.

## Current proof of concept

The implementation currently supports:

- PCAP-derived RDP and SMB observations joined with Windows Security events
  `4624`, `4672`, and `4648`;
- successful AWS CloudTrail `sts:AssumeRole` transitions;
- explicit, evidence-referenced cross-environment identity mappings;
- route-policy outcomes of `AUTHORIZED`, `PROHIBITED`, or `UNKNOWN_CONTEXT`;
- deterministic offline reconstruction and evidence-referenced reports.

The committed fixtures are synthetic so that ground truth, privacy, negative
controls, ambiguous cases, and workshop timing can be controlled. The case runner
can process real PCAP, EVTX, JSON, NDJSON, Elasticsearch exports, and CloudTrail
records stored outside the repository. Synthetic validation demonstrates intended
functional behavior and reproducibility; it does not establish production
accuracy, scalability, or generalization.

## What is not claimed

This work does not claim to invent tiered administration or privileged-access
workstations, introduce a new machine-learning algorithm, outperform anomaly
detectors, reconstruct syscall-level provenance, or provide a production-ready
forensic engine. The SME perspective informs the design requirements, but
operational effectiveness across representative SMEs has not yet been established.
That requires real-lab cases, practitioner evaluation, and broader field studies.

## Evaluation direction

The proof of concept is evaluated through falsifiable cases using the same input
with individual safeguards enabled and disabled:

1. an entitled identity uses an unapproved route to a critical asset;
2. a loose same-user/time correlation fabricates a pivot that strict session
   lineage must reject;
3. identical evidence, policy, parameters, and code reproduce the same stable
   derivation identifier.

Future validation should add independently collected on-premises and cloud
evidence, measure processing time and abstention behavior, and obtain feedback
from SME practitioners without expanding the present claims prematurely.
