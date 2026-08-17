# Privileged Pivot Progression

**Problem:** single-host detections can identify a privileged logon, but they
cannot show whether that session *created a new path* to another host, *crossed an
administrative boundary*, or *expanded access toward critical assets*. That is the
administrative blind spot. This unit reconstructs the progression from network,
authentication, privilege, and organisational context.

**Techniques:** [T1021.001](https://attack.mitre.org/techniques/T1021/001/) ·
[T1021.002](https://attack.mitre.org/techniques/T1021/002/) ·
[T1078.002](https://attack.mitre.org/techniques/T1078/002/)
**Tactic:** Lateral Movement (TA0008) · **Status:** development

> Note on tactics: this maps to Lateral Movement and Valid Accounts. It does **not**
> claim Privilege Escalation merely because an administrator logged in — that
> mapping belongs only where there is evidence of an actual privilege transition.

## Two layers

| Layer | Where | Job |
|---|---|---|
| **Edge establishment** | `query.eql` (Elastic) | Emit one privileged pivot EDGE CANDIDATE: network RDP/SMB → 4624 → 4672 on the target. |
| **Progression** | `automation/{build_reachability_graph,classify_pivot_progression}.py` | Chain edges across hosts, enforce identity continuity, apply tier/role context, classify. |

Elastic generates **edge candidates**; Python maintains **state across hosts** and
(these are edge *candidates*, not trustworthy edges: the strict session joins are
enforced by the materializer, `automation/materialize_pivot_edges.py`)
identifies progression. This is why the automation layer exists — it is the
analytic, not a validator.

## The detection model

| State | Required evidence | Meaning |
|---|---|---|
| Pivot established | network connection + matching successful auth | Host A reached Host B |
| Privileged session | 4672 (privileges assigned to the logon session), correlated to the 4624 logon id | Sensitive privileges were assigned to the session — evidence of capability, not proof of malicious use |
| Credential transition | 4648 or correlated identity change | Different credentials may have enabled progression |
| Pivot progression | B becomes the source of a later authenticated connection to C | Access is propagating |
| Privileged reach expansion | new edge / unapproved path / higher-tier destination | The administrative blind spot |

## The invariant

```
first.target == next.source
AND (same identity OR correlated credential transition)
AND next target is new-to-identity OR higher tier
AND progression occurs within the window
```

A network connection alone cannot establish identity continuity, so each hop
needs authentication evidence; otherwise the result is labelled
`INSUFFICIENT_EVIDENCE` (lower confidence).

## Classifications (aligned with the FIRE label vocabulary)

`NONE` · `INSUFFICIENT_EVIDENCE` · `INSUFFICIENT_CONTEXT` · `EXPECTED` · `JUSTIFIED` ·
`PIVOT_PROGRESSION` · `POSSIBLE_PRIVILEGED_PROGRESSION` · `PRIVILEGED_PROGRESSION` ·
`PRIVILEGED_DESTINATION_REACH` · `CREDENTIAL_TRANSITION_PROGRESSION` · `CRITICAL_UNAPPROVED_PATH`

Entitlement (may the identity reach Tier 0?) and route authorization (was the
sanctioned path used?) are independent — a Tier-0 reach by an unapproved route is
`CRITICAL_UNAPPROVED_PATH` even for an entitled Domain Admin. Full table:
`automation/context/VOCABULARY.md`.

## Contracts

Layers speak through frozen schemas in `schemas/` (`pivot_edge`,
`progression_finding`, `context`), validated in CI by `validate_schemas.py` and
`validate_context.py`. Edge materialization from raw ECS + Windows events is
**implemented** in `automation/materialize_pivot_edges.py` (strict service/LogonType,
IP and logon-id joins, 4648 on the outgoing hop, session lineage) and exercised
end-to-end by `automation/test_pipeline.py`. The EQL rule remains an edge
*candidate* generator; the materializer is what makes an edge trustworthy.

## Context (a hard dependency)

Classification is meaningless without context. `automation/context/` ships small,
documented fixtures — `asset_tiers.yml`, `identity_roles.yml`,
`expected_admin_paths.yml`, `approved_changes.yml` — the portfolio analogue of
FIRE's pre-committed context files. In production these come from an asset
inventory and IAM.

## Validation

- **Edge rule** (`test_data/true_positive.json` / `false_positive.json`): executed
  by the EQL harness — network+4624+4672 fires; the same without 4672 does not.
- **Progression** (`test_data/scenarios/`): 19 scenarios (baseline + adversarial: unknown/unconfirmed transition, source- and destination-session privilege, session lineage, unknown intermediate, unauthenticated standalone, distinct identities, approval window) executed by
  `automation/test_progression.py` with **exact** assertions (label, path,
  confidence, and count — not just "label appears"). They cover the approved PAW
  path, the unapproved Domain-Admin route to a DC (`CRITICAL_UNAPPROVED_PATH`),
  non-privileged pivots, credential transitions, expired approvals, missing
  context, wrong identity, and out-of-window hops.

## Honest boundaries

- **Bounded, not a full graph engine.** Arbitrary-length reachability is a graph
  analytic — the FIRE engine. This shows an honest bounded slice (2-hop edges +
  context-based classification) and points to FIRE for the general case.
- **Context-gated.** Without tier/role context nothing meaningful fires; the
  context is a stated dependency, committed as fixtures.
- **Edge quality** depends on the sensor's flow model; the bidirectional-flow
  refactor (tracked separately) improves the network half of each edge.
