# Progression output vocabulary

| Label | Meaning |
|---|---|
| `NONE` | Authenticated session, no qualifying onward movement. |
| `INSUFFICIENT_EVIDENCE` | A hop lacks confirmed authentication (edge not established). |
| `INSUFFICIENT_CONTEXT` | Host or identity is not declared in context; cannot judge. |
| `EXPECTED` | Baseline administrative behavior (matches a sanctioned admin path). |
| `JUSTIFIED` | Explicit approval / change ticket authorizes the new access. |
| `PIVOT_PROGRESSION` | Onward movement, non-privileged. |
| `PRIVILEGED_PROGRESSION` | Onward movement launched FROM a confirmed privileged session (source). |
| `POSSIBLE_PRIVILEGED_PROGRESSION` | Source-privileged onward move whose session lineage is only identity-level (not session-exact). |
| `PRIVILEGED_DESTINATION_REACH` | Onward movement ESTABLISHED a privileged session on the destination. |
| `CREDENTIAL_TRANSITION_PROGRESSION` | Progression enabled by a correlated credential change (4648). |
| `CRITICAL_UNAPPROVED_PATH` | Reaches a Tier-0/critical asset by an unauthorized route — regardless of entitlement. |

Entitlement (may the identity reach Tier 0 at all?) and route authorization (was
the sanctioned path used?) are **independent**. A Domain Admin entitled to Tier 0
who reaches a DC by an unapproved route is `CRITICAL_UNAPPROVED_PATH`.
