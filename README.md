# ThreatShield — Realtime Blacklist & Threat Monitoring Platform

ThreatShield is a full-stack platform for monitoring an organization's external
attack surface: domains, IP addresses, and URLs. It continuously (or
on-demand) checks 28 public DNS-based blacklists (DNSBLs), SSL certificates,
domain expiry, DNS records, open ports, HTTP security headers, SPF/DKIM/DMARC
email security, and optionally AbuseIPDB — rolling those findings into a
single threat score per asset, raising alerts, and notifying your team by
email, Telegram, or Slack.

The UI is a dark-sidebar security console: a monitoring dashboard, per-asset
tabbed detail pages (SSL / DNS / Server Status / AbuseIPDB / WHOIS /
Blacklist), and a "Check & Lookup" toolbox of standalone ad-hoc scanners that
don't require registering an asset first — plus a public landing page with a
no-login-required quick blacklist check.

Built with **FastAPI**, **SQLAlchemy**, **Alembic**, **APScheduler**, and a
hand-built Jinja2 + vanilla CSS/JS frontend (light/dark theme toggle, no CSS
framework lock-in). Ships with a REST API (OpenAPI/Swagger docs included),
PDF/CSV/Excel reporting, Docker Compose deployment, and a Prometheus/Grafana
monitoring stack.

> This project was built as a final-year engineering / portfolio project. It
> is functional and end-to-end tested, but the scanning techniques (DNS,
> WHOIS, TLS inspection, TCP connect-scan, public DNSBL lookups, HTTP header
> analysis) are standard, publicly documented techniques intended for
> monitoring assets **you own or are authorized to test**. Do not point it at
> systems you don't have permission to scan.

---

## Features

- 🔐 JWT authentication, bcrypt password hashing, role-based access control (admin / analyst / viewer)
- 📊 Dashboard: monitoring summary stats and per-asset blacklist check history
- 🌐 Asset management for domains, IPs, and URLs — card-based asset list, tabbed asset detail view
- 🔍 Automated checks: DNS records, WHOIS/domain expiry, SSL certificate expiry, TCP port scanning, HTTP security headers, 28-provider DNSBL blacklist/reputation
- ✉️ SPF / DKIM / DMARC email security checks
- 🛡️ Optional AbuseIPDB integration (bring your own free API key)
- 🧰 Standalone "Check & Lookup" toolbox: Blacklist Check, Bulk Check, Subnet/CIDR Check, AbuseIPDB, WHOIS Lookup, DNS Records, SSL Checker, SPF/DKIM/DMARC, Is Server Up? — usable without registering an asset
- 🌍 Public landing page with a no-login quick blacklist check
- 🧮 Transparent, weighted threat-score calculation (0–100) with risk levels (low/medium/high/critical)
- ⏰ Background scheduler (APScheduler) for automatic recurring scans
- 🔔 Alerts with email / Telegram / Slack notification delivery
- 🔗 Genuine per-provider delisting links (not a fake "delist" button — DNSBL delisting has to be attested by the listed party on the provider's own site)
- 📄 PDF, CSV, and Excel report generation with executive summary and recommendations
- 📝 Audit logging of security-relevant actions
- 🖥️ REST API with Swagger/OpenAPI docs at `/docs`
- 🌗 Light/dark theme toggle
- 🐳 Docker Compose stack: app, PostgreSQL, Nginx, Prometheus, Grafana
- ✅ Pytest test suite (27 tests covering auth, RBAC, assets, reports, threat scoring, validators, blacklist result grouping)

## Tech Stack

| Layer         | Technology                                             |
|---------------|---------------------------------------------------------|
| Backend       | Python 3.12, FastAPI, SQLAlchemy, Alembic, APScheduler   |
| Frontend      | Jinja2, hand-built CSS design system, vanilla JS         |
| Database      | PostgreSQL (production), SQLite (development)            |
| Auth          | JWT (python-jose), Passlib/bcrypt                        |
| Reports       | ReportLab (PDF), openpyxl (Excel), csv (stdlib)          |
| Deployment    | Docker, Docker Compose, Nginx                            |
| Monitoring    | Prometheus, Grafana                                      |
| Testing       | Pytest, FastAPI TestClient                               |
| CI            | GitHub Actions                                            |

## Documentation

- [Installation Guide](docs/INSTALLATION.md)
- [User Guide](docs/USER_GUIDE.md)
- [Developer Guide](docs/DEVELOPER_GUIDE.md)
- [Deployment Guide](docs/DEPLOYMENT.md)
- [API Documentation](docs/API.md)
- [Architecture & Diagrams](docs/ARCHITECTURE.md)

## Quick Start (local, SQLite)

```bash
git clone <your-fork-url> threatshield
cd threatshield
python3 -m venv venv
source venv/bin/activate            # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
alembic upgrade head
python seed_data.py                 # optional: sample users/assets
uvicorn app.main:app --reload
```

Visit **http://localhost:8000/login**. If you ran `seed_data.py`, log in with
`admin` / `AdminPass123`. Otherwise, register a new account at `/register`
(new accounts default to the read-only `viewer` role — promote yourself to
`admin` via the database or another admin account to unlock user/settings
management).

See [docs/INSTALLATION.md](docs/INSTALLATION.md) for the full command
reference, including Docker Compose.

## Project Structure

```
threatshield/
├── app/
│   ├── models/          # SQLAlchemy ORM models (17 tables)
│   ├── schemas/         # Pydantic request/response schemas
│   ├── services/        # Business logic: scanning, scoring, reports, notifications
│   ├── routers/         # FastAPI route handlers (HTML + REST API), incl. tools.py for standalone lookups
│   ├── scheduler/       # APScheduler jobs for automated scans
│   ├── utils/           # Security, validation, logging helpers
│   ├── templates/       # Jinja2 templates, incl. templates/tools/ for standalone check pages
│   ├── static/          # app-shell.css/js: the dark-sidebar design system
│   ├── main.py          # FastAPI app entrypoint
│   ├── config.py        # Environment-based settings
│   └── database.py      # SQLAlchemy engine/session setup
├── migrations/           # Alembic migrations
├── tests/                 # Pytest test suite
├── docker/                # Dockerfile
├── nginx/                 # Nginx reverse proxy config
├── monitoring/            # Prometheus + Grafana provisioning
├── docs/                  # Documentation
├── seed_data.py            # Sample data loader
├── docker-compose.yml
├── requirements.txt
└── .env.example
```

## License

This is a portfolio / educational project. Use and adapt it freely for
learning purposes.
