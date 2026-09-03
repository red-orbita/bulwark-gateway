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

**OpenCTI** is supported as a pull CTI feed: add a feed of type
`opencti` in the admin UI with your OpenCTI base URL and an API token. Bulwark
queries the `indicators` GraphQL collection, parses each STIX-2 pattern into
atomic IOCs (domains, IPv4/IPv6, URLs, SHA-256/MD5 hashes), drops revoked
indicators and anything below the feed's confidence floor
(`min_confidence` × 100 vs the OpenCTI score), and carries OpenCTI labels
through as tags. The configured URL is validated against the SSRF blocklist on
every fetch.

**MISP** is a first-class connector: pull attributes into the live IOC store, and
(via the **Integrations** surface, `data/integrations.json`) push a case to a MISP
**Event**, look an observable up against `/attributes/restSearch`, and receive
sightings.

### Managed feed from a CTI connector (auto-provisioned)

An OpenCTI/MISP **integration connector** (Integrations surface) can double as an
IOC pull feed without configuring the feed twice. Tick **"Also consume as an IOC
feed"** on the connector — Bulwark provisions a *managed* feed that reuses the
connector's base URL + credential (plus the modal's poll interval and minimum
confidence). The managed feed:

- appears in `/admin/iocs` as read-only with a **"via Integration"** badge — its
  toggle/edit/delete are locked (manage it from the connector; **Run now** is
  still allowed). Its id is `int-<connectorId>` (`managed_by` set).
- is kept in lock-step with the connector: toggling the connector off disables the
  feed (runtime state preserved); disabling the pull option, switching to a
  non-feed connector type, or deleting the connector tears the feed down. A
  hand-made feed of the same name is never clobbered.
- resolves its API key from `BULWARK_INTEGRATION_<ID>_API_KEY` (and its `_FILE`
  Docker-secret variant) in preference to the connector's inline value, falling
  back to inline — so the pull credential can live in your secret store. `<ID>` is
  the connector id upper-cased.

**TAXII 2.1** collections are a vendor-neutral pull feed: add a feed of type
`taxii`; Bulwark polls the collection's STIX 2.1 envelope, parses `indicator`
SDOs into IOCs (same pattern parser as OpenCTI), and upserts them into the live
IOC store. Collection URLs are SSRF-validated per fetch.

**Sighting feedback (bidirectional).** When a promoted IOC actually matches proxy
traffic and blocks it, Bulwark can report that **sighting** back upstream to the
platform the indicator came from (OpenCTI `stixSightingRelationship` / MISP
`/sightings/add`), raising its local score. This is off by default
(`BULWARK_SIGHTING_FEEDBACK_ENABLED=true` to enable), admin-side/async (no proxy
hot-path cost), TLP-gated (a `TLP:RED`-tagged indicator is never shared), and
fully audited. Tune the sweep with `BULWARK_SIGHTING_POLL_INTERVAL_SECONDS`,
`BULWARK_SIGHTING_SWEEP_LIMIT`, and `BULWARK_SIGHTING_MAX_PER_SWEEP`.


## Environment Variables (Quick Setup)

For the built-in feeds, set the matching API key:

```bash
BULWARK_URLHAUS_KEY=your-key
BULWARK_THREATFOX_KEY=your-key
BULWARK_OTX_KEY=your-key
BULWARK_ABUSEIPDB_KEY=your-key
```
