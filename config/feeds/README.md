# Threat Intelligence Feeds

Place YAML feed configuration files in this directory.

For threat-intel feed configuration details, see `docs/DEPLOYMENT.md` and the
Features overview in the project `README.md`.

## Examples

No example YAML files ship in this directory by default. Filenames you can create:

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
