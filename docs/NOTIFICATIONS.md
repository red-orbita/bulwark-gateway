# Notification Channels

Enterprise multi-channel alerting for security events (BLOCK, WARN, REDACT).

## Table of Contents
- [Overview](#overview)
- [Supported Channels](#supported-channels)
- [Configuration Methods](#configuration-methods)
- [YAML Configuration](#yaml-configuration)
- [Admin UI](#admin-ui)
- [Email SMTP Setup](#email-smtp-setup)
- [Routing & Filtering](#routing--filtering)
- [Deduplication](#deduplication)
- [Generic Webhook Auth](#generic-webhook-auth)
- [Legacy Environment Variable](#legacy-environment-variable)
- [Testing Channels](#testing-channels)
- [Architecture](#architecture)

## Overview

Sentinel Gateway fires real-time notifications when security events occur (input blocked, output redacted, policy violation). Notifications are:
- **Non-blocking**: dispatched via asyncio fire-and-forget (zero latency impact on proxy)
- **Deduplicated**: same alert not sent twice within configurable window
- **Routable**: filter by severity, verdict type, and tenant
- **Multi-source**: configure via YAML (GitOps), Admin UI, or legacy env var

## Supported Channels

| Channel | Type Key | Required Fields | Rich Formatting |
|---------|----------|-----------------|-----------------|
| Slack | `slack` | `url` (Incoming Webhook) | Block Kit |
| Microsoft Teams | `teams` | `url` (Incoming Webhook) | Adaptive Cards |
| Discord | `discord` | `url` (Webhook URL) | Embeds |
| PagerDuty | `pagerduty` | `routing_key` (Integration Key) | Events API v2 |
| Opsgenie | `opsgenie` | `api_key` | Alert API |
| Telegram | `telegram` | `bot_token`, `chat_id` | Markdown |
| Google Chat | `google_chat` | `url` (Webhook URL) | Cards |
| Email (SMTP) | `email` | `smtp_host`, `smtp_to` | HTML |
| Generic Webhook | `generic` | `url` | JSON payload |

## Configuration Methods

Channels can be defined from multiple sources (merged at startup):

1. **YAML file** (`config/notifications.yaml`) — GitOps, version-controlled
2. **Admin UI** (`/notifications`) — stored in `shared/notifications/channels.json`
3. **Environment variable** (`SENTINEL_WEBHOOK_ALERT_URLS`) — legacy, backward-compatible

Priority: Admin UI channels load first, then YAML (skips duplicates by ID), then env var.

## YAML Configuration

Edit `config/notifications.yaml`:

```yaml
channels:
  - id: slack-security
    name: "#security-alerts"
    type: slack
    enabled: true
    url: "https://hooks.slack.example.com/services/TXXXXXXXX/BXXXXXXXX/placeholder-token"
    min_severity: high
    verdicts: [block, warn]
    tenants: []               # empty = all tenants
    dedup_window_seconds: 300

  - id: teams-soc
    name: "SOC Channel"
    type: teams
    enabled: true
    url: "https://outlook.office.com/webhook/xxx/IncomingWebhook/yyy/zzz"
    min_severity: high
    verdicts: [block]

  - id: email-soc
    name: "SOC Team Email"
    type: email
    enabled: true
    smtp_host: "smtp.gmail.com"
    smtp_port: 587
    smtp_user: "alerts@company.com"
    smtp_password: "app-password"
    smtp_from: "alerts@company.com"
    smtp_to:
      - "soc@company.com"
      - "security-lead@company.com"
    smtp_tls: starttls
    min_severity: critical
    verdicts: [block]
    dedup_window_seconds: 600

  - id: pagerduty-oncall
    name: "On-Call Escalation"
    type: pagerduty
    routing_key: "your-integration-key"
    min_severity: critical
    verdicts: [block]

  - id: telegram-admin
    name: "Admin Bot"
    type: telegram
    bot_token: "123456789:ABCdefGHI..."
    chat_id: "-1001234567890"
    min_severity: high
    verdicts: [block]

  - id: discord-alerts
    name: "Discord Alerts"
    type: discord
    url: "https://discord.com/api/webhooks/000/xxx"
    min_severity: critical

  - id: opsgenie-team
    name: "Security Team"
    type: opsgenie
    api_key: "your-opsgenie-api-key"
    min_severity: high
    verdicts: [block, warn]

  - id: gchat-security
    name: "Security Space"
    type: google_chat
    url: "https://chat.googleapis.com/v1/spaces/SPACE_ID/messages?key=KEY&token=TOKEN"
    min_severity: high

  - id: webhook-soar
    name: "SOAR Platform"
    type: generic
    url: "https://soar.company.com/api/v1/incidents"
    headers:
      X-Custom-Header: "sentinel-gateway"
    auth_type: bearer
    auth_value: "your-bearer-token"
    min_severity: medium
    verdicts: [block, warn, redact]
```

## Admin UI

Navigate to `/notifications` in the admin portal (requires `notifications:write` permission).

### Features
- **Add Channel** — wizard with type-specific fields
- **Test** — sends a test notification to verify connectivity
- **Toggle** — enable/disable without deleting configuration
- **Delete** — permanently remove channel
- **Reload** — re-read from disk (picks up YAML changes)

### API Endpoints

```
GET    /admin/notifications/channels              # List all channels
POST   /admin/notifications/channels              # Create channel
PUT    /admin/notifications/channels/{id}         # Update channel
DELETE /admin/notifications/channels/{id}         # Delete channel
POST   /admin/notifications/channels/{id}/test   # Send test notification
POST   /admin/notifications/channels/{id}/toggle # Enable/disable
POST   /admin/notifications/reload               # Reload from disk/YAML
```

### RBAC Permissions

| Permission | Roles |
|-----------|-------|
| `notifications:read` | admin, security, auditor, viewer |
| `notifications:write` | admin, security |

## Email SMTP Setup

### Provider-Specific Configuration

| Provider | Host | Port | TLS | Username | Password | Notes |
|----------|------|------|-----|----------|----------|-------|
| **Gmail** | `smtp.gmail.com` | 587 | starttls | Your email | App Password | Generate at myaccount.google.com/apppasswords |
| **Office 365** | `smtp.office365.com` | 587 | starttls | Your email | Account password | Enable SMTP AUTH in Exchange admin |
| **SendGrid** | `smtp.sendgrid.net` | 587 | starttls | `apikey` (literal) | Your API key | Create API key at sendgrid.com |
| **AWS SES** | `email-smtp.<region>.amazonaws.com` | 587 | starttls | SMTP credential | SMTP credential | Generate in SES console |
| **Mailgun** | `smtp.mailgun.org` | 587 | starttls | Your domain login | Password | Check Mailgun dashboard |
| **Custom relay** | Your host | 25 or 587 | none/starttls | Optional | Optional | Internal relay |

### Gmail Setup

1. Enable 2-Factor Authentication on your Google account
2. Go to https://myaccount.google.com/apppasswords
3. Generate an App Password for "Mail"
4. Use that 16-character password as `smtp_password`

### Office 365 Setup

1. In Exchange Admin Center → Mail flow → Connectors
2. Enable "Authenticated SMTP" for the sending account
3. Or use a shared mailbox with SMTP AUTH enabled

### SendGrid Setup

1. Create an API key at https://app.sendgrid.com/settings/api_keys
2. Set `smtp_user: "apikey"` (literally the string "apikey")
3. Set `smtp_password: "SG.your-api-key-here"`

### TLS Modes

| Mode | Port | Behavior |
|------|------|----------|
| `starttls` | 587 | Connects plain, upgrades to TLS via STARTTLS command |
| `ssl` | 465 | Connects directly over SSL/TLS |
| `none` | 25 | No encryption (internal relay only) |

## Routing & Filtering

Each channel has independent routing rules:

### Severity Levels

```
low < medium < high < critical
```

`min_severity` sets the threshold — only events at that level or above trigger the notification.

| min_severity | Triggers on |
|-------------|-------------|
| `low` | All events |
| `medium` | medium, high, critical |
| `high` | high, critical |
| `critical` | critical only |

### Verdict Filter

```yaml
verdicts: [block, warn, redact]
```

Only specified verdicts trigger the notification. Common configurations:
- `[block]` — Only actual blocks (most common for pagers)
- `[block, warn]` — Blocks and warnings (good for Slack)
- `[block, warn, redact]` — Everything (good for SIEM/audit)

### Tenant Filter

```yaml
tenants: ["tenant-a", "tenant-b"]  # Only these tenants
tenants: []                         # All tenants (default)
```

## Deduplication

Each channel maintains its own dedup window. The dedup key is computed from:

```
SHA256(category + tenant_id + description)[:16]
```

If the same key was sent to the same channel within `dedup_window_seconds`, it's suppressed.

```yaml
dedup_window_seconds: 300   # 5 minutes (default)
dedup_window_seconds: 600   # 10 minutes (good for email)
dedup_window_seconds: 60    # 1 minute (for fast response channels)
dedup_window_seconds: 0     # Disable dedup (send every alert)
```

## Generic Webhook Auth

For custom webhook destinations that require authentication:

```yaml
  - id: custom-endpoint
    type: generic
    url: "https://api.company.com/security/alerts"
    auth_type: bearer       # Options: none, bearer, api_key
    auth_value: "your-token"
    headers:
      X-Source: "sentinel-gateway"
      X-Environment: "production"
```

| Auth Type | Behavior |
|-----------|----------|
| `none` | No auth header added |
| `bearer` | Adds `Authorization: Bearer <auth_value>` |
| `api_key` | Adds `X-API-Key: <auth_value>` |

## Legacy Environment Variable

For backward compatibility, the `SENTINEL_WEBHOOK_ALERT_URLS` env var still works:

```bash
# Format: type|name|url (comma-separated for multiple)
SENTINEL_WEBHOOK_ALERT_URLS="slack|alerts|https://hooks.slack.com/...,generic|soar|https://soar.company.com/..."
```

These are loaded at startup with default routing (min_severity=high, verdicts=[block]).

## Testing Channels

### Via Admin UI

Click the "Test" button on any channel card. A test notification is sent with:
- Verdict: BLOCK
- Severity: HIGH
- Category: test
- Description: "This is a test notification..."

### Via API

```bash
curl -X POST http://localhost:8090/admin/notifications/channels/<channel-id>/test \
  -H "Authorization: Bearer $TOKEN"
```

Response:
```json
{"success": true, "message": "Test notification sent successfully"}
// or
{"success": false, "message": "Connection refused..."}
```

## Architecture

```
┌─────────────┐    SecurityEvent    ┌────────────────────┐
│   Proxy     │──────────────────▶  │ NotificationEngine │
│ (hot path)  │  fire-and-forget    │   (singleton)      │
└─────────────┘                     └────────┬───────────┘
                                             │
                              ┌──────────────┼──────────────┐
                              │              │              │
                        ┌─────▼─────┐  ┌────▼────┐  ┌─────▼─────┐
                        │  Channel  │  │ Channel │  │  Channel  │
                        │  (Slack)  │  │ (Email) │  │ (PD/OG)   │
                        └───────────┘  └─────────┘  └───────────┘
```

- **Zero latency impact**: notifications dispatched as asyncio tasks, never block the request
- **Graceful failure**: if a channel fails, it logs a warning but doesn't affect other channels
- **Memory-bounded dedup**: cache limited to 2000 entries, auto-purged after 10 minutes
- **Persistent config**: Admin-managed channels saved to `shared/notifications/channels.json`
