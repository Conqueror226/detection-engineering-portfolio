# Anomalous RC4 Kerberos TGT Request (Potential Overpass-the-Hash)

**Technique:** [T1550.002 — Use Alternate Authentication Material: Pass the Hash](https://attack.mitre.org/techniques/T1550/002/)
**Tactic:** Lateral Movement (TA0008)
**Language:** EQL · **Category:** signature · **Status:** development (hunt)

---

## Hypothesis

A Kerberos TGT issued for a **user** account with **RC4-HMAC (0x17)** encryption
is worth a look in a domain that has standardised on AES. Overpass-the-hash can
produce RC4 tickets (a stolen NTLM hash *is* the RC4 key), but this is an
**environment-dependent indicator, not a fingerprint**:

- **Not necessary** — an attacker with the AES keys can pass AES tickets and never
  touch RC4.
- **Not sufficient** — legacy accounts, cross-realm trusts, and domains
  mid-migration to AES all emit RC4 legitimately.

So a match is a **lead to correlate**, not evidence. Its value depends entirely on
the environment being AES-standardised first.

Analogy: in an office that switched to keycards, someone using an old metal key
*might* be an intruder — or the one contractor who never got a card. The old key
is a reason to check, not a verdict.

## Logic

A single-event match on **Event 4768** (TGT issued):

- `TicketEncryptionType == 0x17` (RC4-HMAC)
- exclude machine accounts (`TargetUserName` ending in `$`)
- exclude `krbtgt` and empty names

## Data source

- Windows Security Event Log — Event ID 4768 (Kerberos authentication ticket requested)

## Validation

| File | Expectation |
|---|---|
| `test_data/true_positive.json` | User TGT with RC4 (0x17) → rule should fire |
| `test_data/false_positive.json` | AES TGT and a machine-account RC4 TGT → rule should not fire |

## Tuning notes

- **Baseline first — this is the whole ballgame.** Confirm the domain is genuinely
  AES-standardised before enabling; during an AES migration this rule is high-noise.
- Allowlist known **legacy/interop accounts** that require RC4.
- Correlate, don't alert in isolation: pair with the RDP detection
  (credential upgrade → remote pivot) and with privileged-account context. A
  privileged `TargetUserName` here is where the FIRE privilege-drift labels apply.
- Because confidence is environment-dependent, this ships at **medium** severity —
  raise it locally only once your baseline justifies it.
