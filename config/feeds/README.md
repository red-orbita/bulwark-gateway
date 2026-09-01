# Threat Intelligence Feeds

Place YAML feed configuration files in this directory.

For threat-intel feed configuration details, see `docs/DEPLOYMENT.md` and the
Features overview in the project `README.md`.

## Built-in feeds

Four threat-intel feeds ship and are configured by API key (see below), not by
YAML file: **URLhaus**, **ThreatFox** (abuse.ch), **AlienVault OTX**, and
**AbuseIPDB**. Managed feeds are administered from the admin UI (`/admin/iocs`)
and persisted server-side — dropping a YAML file here is not auto-loaded.

## CTI connectors (managed, URL + key)

**OpenCTI** is supported as a pull-only CTI connector: add a feed of type
`opencti` in the admin UI with your OpenCTI base URL and an API token. Bulwark
queries the `indicators` GraphQL collection, parses each STIX-2 pattern into
atomic IOCs (domains, IPv4/IPv6, URLs, SHA-256/MD5 hashes), drops revoked
indicators and anything below the feed's confidence floor
(`min_confidence` × 100 vs the OpenCTI score), and carries OpenCTI labels
through as tags. The configured URL is validated against the SSRF blocklist on
every fetch. Bulwark does **not** push data back to OpenCTI.


## Environment Variables (Quick Setup)

For the built-in feeds, set the matching API key:

```bash
BULWARK_URLHAUS_KEY=your-key
BULWARK_THREATFOX_KEY=your-key
BULWARK_OTX_KEY=your-key
BULWARK_ABUSEIPDB_KEY=your-key
```
