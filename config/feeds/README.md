# Threat Intelligence Feeds

Place YAML feed configuration files in this directory.

See the main README.md section "Threat Intelligence Feeds" for configuration details.

## Examples

- `misp.yaml` — MISP threat sharing platform
- `custom-internal.yaml` — Custom internal threat intel API

## Environment Variables (Quick Setup)

For simple feeds, use environment variables instead of YAML:

```bash
BULWARK_URLHAUS_KEY=your-key
BULWARK_THREATFOX_KEY=your-key
BULWARK_OTX_KEY=your-key
BULWARK_ABUSEIPDB_KEY=your-key
```
