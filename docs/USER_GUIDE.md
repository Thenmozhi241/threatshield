# User Guide

## Signing up and logging in

Go to `/register` to create an account. New accounts are assigned the
read-only **viewer** role by default. An existing admin can promote your
account to **analyst** (can manage assets and run scans) or **admin** (full
access, including user/settings management) from the **Users** page.

## Adding an asset

1. Go to **Assets → + Add Asset**.
2. Enter a domain name (e.g. `example.com`) or IP address (e.g. `203.0.113.10`).
3. Choose the asset type, add an optional description and comma-separated tags.
4. Click **Add Asset**.

Only valid domain names or IP addresses are accepted — this is validated
both client-side and server-side.

## Running a scan

On any asset's detail page, click **Run Scan Now**. This performs, in order:

1. **DNS lookup** (domains only) — A, AAAA, MX, TXT, NS, CNAME, SOA records
2. **WHOIS lookup** (domains only) — registrar, registration/expiry dates, name servers
3. **SSL certificate check** — issuer, validity window, days until expiry
4. **HTTP security header analysis** — checks for HSTS, CSP, X-Frame-Options, etc.
5. **TCP port scan** — checks ~17 common ports for open/closed status
6. **Reputation/blacklist check** — queries public DNSBLs (Spamhaus, SpamCop, Barracuda)
7. **Threat score calculation** — combines all findings into a single 0–100 score
8. **Alert generation** — raises alerts for expiring certs/domains, risky open ports, blacklisting, and elevated threat scores
9. **Notification dispatch** — sends any new alerts via the enabled channels (email/Telegram/Slack)

Scans typically take a few seconds to under a minute, depending on network
latency to the target and how many checks apply (IP assets skip DNS/WHOIS).

## Automatic scans

If enabled (`SCHEDULER_ENABLED=true` in `.env`, the default), the platform
automatically re-scans every **active** asset every `SCAN_INTERVAL_HOURS`
hours (default: 24) — no manual action needed.

## Alerts

The **Alerts** page lists all alerts, newest first, with severity
(info/warning/critical), category, and status. Click **Resolve** to mark an
alert as handled. Resolved alerts remain in history for audit purposes.

## Reports

The **Reports** page lets you generate a report for a single asset or the
whole organization, in PDF, CSV, or Excel format. Each report includes an
executive summary, per-asset threat score, open findings, and remediation
recommendations. Previously generated reports remain downloadable from the
same page.

## Admin: Users & Settings

Admins can access **Users** (create accounts, assign roles, activate/deactivate
users) and **Settings** (adjust the scan interval and notification toggles).
Notification *credentials* (SMTP password, Telegram bot token, Slack webhook
URL) are configured via environment variables rather than the Settings page,
to avoid storing secrets in the database.

## REST API

Every action available in the UI is also available as a JSON REST endpoint
under `/api/...` — see the interactive docs at `/docs` (Swagger UI) or
[docs/API.md](API.md).
