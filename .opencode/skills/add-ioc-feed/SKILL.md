# Skill: Add IOC Feed

## Purpose
Integrate a new threat intelligence feed into the IOC database.

## Workflow

1. **Identify the feed**:
   - URLhaus (abuse.ch) — malicious URLs
   - ThreatFox (abuse.ch) — IOCs (domains, IPs, hashes)
   - AlienVault OTX — pulses with IOCs
   - AbuseIPDB — malicious IPs
   - MISP — structured threat intel
   - Custom feeds (JSON/CSV)

2. **Create importer script**: `scripts/import_<feed_name>.py`
   ```python
   #!/usr/bin/env python3
   """Import IOCs from <feed_name>."""
   import json
   import httpx
   from pathlib import Path

   IOC_PATH = Path("config/iocs.json")

   def fetch_feed() -> dict:
       """Fetch and parse the feed."""
       resp = httpx.get("<feed_url>", timeout=30)
       resp.raise_for_status()
       # Parse response into {"domains": [], "ips": [], "urls": []}
       ...

   def merge_iocs(existing: dict, new: dict) -> dict:
       """Merge new IOCs into existing database."""
       for key in ("domains", "ips", "urls", "hashes"):
           existing_set = set(existing.get(key, []))
           new_set = set(new.get(key, []))
           existing[key] = sorted(existing_set | new_set)
       return existing

   def main():
       existing = json.loads(IOC_PATH.read_text()) if IOC_PATH.exists() else {}
       new = fetch_feed()
       merged = merge_iocs(existing, new)
       IOC_PATH.write_text(json.dumps(merged, indent=2))
       print(f"IOCs updated: {sum(len(v) for v in merged.values())} total")

   if __name__ == "__main__":
       main()
   ```

3. **Create update orchestrator** (if not exists): `scripts/update_iocs.sh`
   ```bash
   #!/bin/bash
   set -e
   echo "[*] Updating IOC database..."
   python3 scripts/import_urlhaus.py
   python3 scripts/import_threatfox.py
   # Add new feed here
   python3 scripts/import_<feed_name>.py
   echo "[+] Done"
   ```

4. **Test IOC loading**:
   ```bash
   pytest tests/test_ioc.py -v
   ```

5. **Verify no false positives**: Check that common legitimate domains aren't in the feed

## IOC Database Format

```json
{
  "domains": ["evil.com", "malware.xyz"],
  "ips": ["185.220.101.1"],
  "urls": ["http://evil.com/payload.sh"],
  "hashes": ["sha256:abc123..."]
}
```

Also supports opencode-security-agent format:
```json
{
  "indicators": [
    {"type": "domain", "value": "evil.com", "source": "urlhaus", "date": "2026-01-01"}
  ]
}
```
