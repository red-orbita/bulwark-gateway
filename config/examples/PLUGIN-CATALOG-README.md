# Signed Plugin Catalog — Example

Bulwark ships **no public plugin marketplace**. Instead, an operator curates a
JSON list of vetted scanner plugins and signs it with their **own** Ed25519 key.
The admin service verifies that signature (against the public key you configure)
before showing any entry or allowing a one-click install — so the catalog is your
supply-chain allowlist, and it is **fail-closed**: no key, no signature, or a
tampered file ⇒ zero installable entries.

This directory contains a **format example only** (`plugin-catalog.example.json`
and its detached signature `plugin-catalog.example.json.sig`). The `git_url` in it
points at `example.com` and is **not installable** — it exists solely to show the
schema and let you test the verify path.

## Production setup (do NOT use the example key)

1. Generate your own keypair (out-of-band, on a trusted workstation):

   ```bash
   python scripts/sign-catalog.py generate-key --out catalog-key
   ```

   This writes `catalog-key.key` (private, mode `0600`, keep it secret — never
   commit it; `.gitignore` blocks `*.key`) and `catalog-key.pub` (public, hex).

2. Configure the admin service with the **public** key (the 64-char hex the
   command prints):

   ```bash
   BULWARK_PLUGIN_CATALOG_PUBKEY=<your-64-char-hex-public-key>
   # or the Docker-secret variant:
   BULWARK_PLUGIN_CATALOG_PUBKEY_FILE=/run/secrets/plugin-catalog-pubkey
   ```

3. Author your catalog at `config/plugin-catalog.json` (override the path with
   `BULWARK_PLUGIN_CATALOG_PATH`), listing only plugins you have vetted. Each
   entry: `name`, `git_url` (HTTPS), optional `branch` (default `main`),
   `description`, `author`, `version`, `category`, `homepage`, `tags`.

4. Sign it (re-sign after every edit — the signature covers the exact bytes):

   ```bash
   python scripts/sign-catalog.py sign \
       --catalog config/plugin-catalog.json --key catalog-key.key
   ```

   This writes `config/plugin-catalog.json.sig` next to it.

5. Deploy both `config/plugin-catalog.json` and its `.sig`. The admin
   **Plugins → Catalog** page now lists your verified entries; one-click install
   reuses the same Git clone + AST + regex security gate as a manual install.

## Example key (for testing the verify path only)

The bundled `plugin-catalog.example.json.sig` was produced with this throwaway
example keypair. It is published **only** so you can exercise verification; never
use it in production (its private key is public, below).

- **Public key** (`BULWARK_PLUGIN_CATALOG_PUBKEY` to trust the example):

  ```
  b6b9cf93d874e62a8d97b43e2916d1a8c0f0a88f4cd06a8ceb16f498e7523128
  ```

- **Private key** (intentionally disclosed — DO NOT reuse):

  ```
  98404fbc9bf14d8ebd413dd463d56270734bc9036bdf48b4d1ae9cb53c8e5ec9
  ```

Verify the example locally:

```bash
printf '%s\n' b6b9cf93d874e62a8d97b43e2916d1a8c0f0a88f4cd06a8ceb16f498e7523128 > /tmp/example.pub
python scripts/sign-catalog.py verify \
    --catalog config/examples/plugin-catalog.example.json --pub /tmp/example.pub
```
