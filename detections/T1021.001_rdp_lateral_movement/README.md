# RDP Lateral Movement Followed by Process Execution

**Technique:** [T1021.001 — Remote Services: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/)
**Tactic:** Lateral Movement (TA0008)
**Language:** EQL (sequence) · **Category:** signature · **Status:** development

---

## Hypothesis

An adversary moving laterally with RDP does not just log in — they *act*.
A successful RemoteInteractive logon (Windows `LogonType 10`) followed within a
short window by process execution under the same identity on the same host is a
stronger signal of hands-on-keyboard activity than an RDP logon alone.

## Logic

An EQL **sequence** correlates two events on the same host (`winlog.computer_name`)
within `maxspan=1m`, joined on the acting identity:

1. **4624** logon, `LogonType == 10`, `event.outcome == success`, non-local source IP
   — keyed by `winlog.event_data.TargetUserName`.
2. **process start** — keyed by `user.name`.

The join on identity is what raises fidelity: it ties the *who logged in* to the
*who ran something*, rather than alerting on any process after any RDP session.

## Data sources

- Windows Security Event Log — Event ID 4624 (successful logon)
- Sysmon Event ID 1 / `process.start`

## Validation

| File | Expectation |
|---|---|
| `test_data/true_positive.json` | Sequence present → rule should fire |
| `test_data/false_positive.json` | Local logon / no matching process → rule should not fire |

## Tuning notes

- Exclude known **jump hosts / bastions** by `winlog.computer_name`.
- Allowlist sanctioned **admin and automation accounts** by `user.name`.
- Widen `maxspan` cautiously — larger windows increase noise on busy servers.
- Consider raising severity if the target account is privileged (ties into the
  privilege-drift labels from the FIRE framework).
