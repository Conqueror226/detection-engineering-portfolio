# Anomalous RC4 Kerberos TGT Request (Potential Overpass-the-Hash)

**Technique:** [T1550.002 — Use Alternate Authentication Material: Pass the Hash](https://attack.mitre.org/techniques/T1550/002/)
**Tactic:** Lateral Movement (TA0008)
**Language:** EQL · **Category:** signature · **Status:** development

---

## Hypothesis

Overpass-the-hash turns a stolen NTLM hash into a *Kerberos* TGT, letting an
attacker stop using NTLM (loud) and start using Kerberos (quiet) for lateral
movement. The tell is the encryption: injection tools request the TGT with
**RC4-HMAC (0x17)**. In a domain that has moved to AES, a *user* account
receiving an RC4 TGT is out of place — the ticket is the fingerprint the attacker
can't easily hide.

Analogy: everyone in the building now badges in with a chip card (AES). Someone
swiping an old magnetic-stripe card (RC4) still gets through the door — but that
outdated card is exactly what gives them away.

## Logic

A single-event match on **Event 4768** (TGT issued):

- `TicketEncryptionType == 0x17` (RC4-HMAC)
- exclude machine accounts (`TargetUserName` ending in `$`)
- exclude `krbtgt` and empty names

No sequence is needed — the anomalous encryption type on a user TGT is itself the
signal. This complements the RDP detection: that one catches the *pivot*, this
one catches the *credential upgrade* that often precedes it.

## Data source

- Windows Security Event Log — Event ID 4768 (Kerberos authentication ticket requested)

## Validation

| File | Expectation |
|---|---|
| `test_data/true_positive.json` | User TGT with RC4 (0x17) → rule should fire |
| `test_data/false_positive.json` | AES TGT and a machine-account RC4 TGT → rule should not fire |

## Tuning notes

- **Baseline first.** Confirm the domain is genuinely AES-only before enabling;
  RC4 during an AES migration will be noisy.
- Allowlist known **legacy/interop accounts** that require RC4.
- Pair with the RDP detection for a stronger lateral-movement narrative: hash
  upgrade (this rule) → remote pivot (T1021.001).
- A privileged `TargetUserName` here should raise severity — this is where the
  FIRE privilege-drift labels become relevant.
