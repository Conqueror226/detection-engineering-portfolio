# Real-evidence validation workflow

This workflow moves the project beyond generated fixtures without putting
sensitive evidence in Git. The committed synthetic case remains the deterministic
CI control; a separately retained Security Onion/Windows lab case supplies the
external-validity evidence.

## 1. Define one authorized case

Start with one bounded RDP or SMB progression because those are the two services
the current materializer supports. Record:

- case identifier and authorized test window in UTC;
- source, pivot, and destination host names and IP addresses;
- test identity and whether it is entitled to the destination;
- sanctioned administrative route;
- expected action sequence, without placing the expected classification in the
  raw evidence directory.

Use dedicated lab accounts and hosts. Do not test on a production network.

## 2. Preserve Windows evidence

On every Windows host that receives a tested hop, export the Security log after
the exercise from an elevated, authorized PowerShell session:

```powershell
wevtutil epl Security C:\Evidence\Security.evtx /ow:true
Get-FileHash C:\Evidence\Security.evtx -Algorithm SHA256
```

The runner reads native EVTX directly and selects Events 4624, 4672, and 4648.
Native EVTX does not contain the local interface IP, so provide an examiner-owned
IP-to-host map. The map is hashed and listed in the manifest.

If using an Elastic export instead, provide ECS/Winlogbeat JSON, NDJSON, or the
complete `_search` response containing `hits.hits[*]._source`. Preserve at least:

- `@timestamp`, `event.code`, `event.outcome`, and `event.id` or
  `winlog.record_id`;
- `host.name`, `host.ip`;
- `winlog.event_data` fields used by 4624, 4672, and 4648.

## 3. Preserve network evidence

Export a PCAP covering the authorized test interval from the monitored lab
segment or the Security Onion PCAP interface. Keep the original capture
unchanged. Record its SHA-256 before analysis:

```bash
sha256sum lab-rdp-pivot-01.pcap
```

The current Scapy sensor parses IPv4 TCP/UDP and materializes RDP (TCP/3389 with
Logon Type 10) and SMB (TCP/445 with Logon Type 3) candidates. Unsupported
protocols remain an explicit limitation.

## 4. Check time and naming before correlation

PCAP timestamps and Windows event timestamps must refer to UTC and should be
NTP-synchronized. First run with no correction. If an independently documented
clock offset exists, pass it explicitly using
`--network-time-offset-seconds`; the applied value is recorded in the manifest.

Create an IP-to-host JSON object whose canonical host names match the context
files. Short names and FQDNs are treated as equivalent only when their aliases
match; the runner does not infer an unrelated host.

## 5. Run the offline reconstruction

```bash
python automation/reconstruct_case.py \
  --case-name lab-rdp-pivot-01 \
  --pcap /secure-evidence/lab-rdp-pivot-01.pcap \
  --windows /secure-evidence/SRV-APP-01-Security.evtx \
  --windows /secure-evidence/DC01-Security.evtx \
  --ip-map /secure-evidence/ip_to_host.json \
  --context-dir automation/context \
  --out-dir /secure-results/lab-rdp-pivot-01
```

Outputs:

| File | Purpose |
|---|---|
| `manifest.json` | Input/output SHA-256 values, parameters, UTC generation time, counts |
| `normalized/*.ndjson` | Representation-normalized network and Windows records |
| `results/data_quality.json` | Missing fields and contract errors |
| `results/pivot_edges.json` | Evidence-supported edges |
| `results/findings.json` | Contextual progression classifications |
| `results/reconstruction_report.md` | Examiner-readable summary and limitations |

## 6. Record validation results without publishing evidence

For the repository, publish only an aggregate validation note after review:

- collection date and environment type (for example, isolated Security Onion
  lab), not routable addresses or account names;
- number of source records, materialized edges, expected and observed findings;
- any missed joins and documented reason;
- software version or commit, parameters, and the manifest SHA-256;
- confirmation that raw artifacts remain in controlled storage.

Do not claim real-world validation until at least one retained case has a reviewed
manifest, data-quality report, and reconstruction report.
