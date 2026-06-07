# Threat Intelligence Feeds

Place YAML feed configuration files in this directory.

See the main README.md section "Threat Intelligence Feeds" for configuration details.

## Examples

- `misp.yaml` — MISP threat sharing platform
- `custom-internal.yaml` — Custom internal threat intel API

## Environment Variables (Quick Setup)

For simple feeds, use environment variables instead of YAML:

```bash
SENTINEL_URLHAUS_KEY=your-key
SENTINEL_THREATFOX_KEY=your-key
SENTINEL_OTX_KEY=your-key
SENTINEL_ABUSEIPDB_KEY=your-key
```
