# Real case workspace

Do not commit raw EVTX, PCAP, exported production events, normalized evidence,
or derived case reports. Keep them in an access-controlled evidence directory
outside the repository and pass their paths to `automation/reconstruct_case.py`.

The repository ignores common evidence formats and case-output directories, but
that is a safety net rather than a handling policy. Confirm `git status` before
every commit.

Minimal host map (`ip_to_host.json`):

```json
{
  "192.168.100.201": "WS-ENG-12",
  "192.168.100.202": "SRV-APP-01",
  "192.168.100.213": "DC01"
}
```

Use the canonical host names that also appear in `automation/context/`.
