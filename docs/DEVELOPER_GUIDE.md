# Developer Guide

## Architecture overview

ThreatShield follows a layered architecture:

```
routers/    → HTTP concerns only (parse request, call a service, render/return response)
services/   → business logic (scanning, scoring, reports, notifications, auth)
models/     → SQLAlchemy ORM definitions (one file per table)
schemas/    → Pydantic request/response validation for the REST API
utils/      → cross-cutting helpers (security, validation, logging)
scheduler/  → background job definitions + APScheduler wiring
templates/  → server-rendered Jinja2 + Bootstrap 5 views
```

Routers never contain scanning/scoring logic directly — they call into
`app/services/*` so the same logic is reusable from the HTML routes, the
JSON API routes, and the background scheduler (see
`app/services/scan_orchestrator.py`, which is the single entry point used by
both `POST /api/scans` and the scheduled job in `app/scheduler/jobs.py`).

## Adding a new scan type

1. Create a new function in `app/services/<name>_service.py` that takes a
   target string and returns a plain dict of findings (never raise on
   expected failures like unreachable hosts — return an `error` key instead,
   following the pattern in `ssl_service.py` / `header_service.py`).
2. Add a corresponding SQLAlchemy model in `app/models/` if the raw findings
   should be persisted, and register it in `app/models/__init__.py`.
3. Wire it into `app/services/scan_orchestrator.run_full_scan()`: call your
   function, persist the result, and (optionally) feed it into
   `threat_score_service.calculate_threat_score()` and `_generate_alerts()`.
4. Generate an Alembic migration: `alembic revision --autogenerate -m "add X"`.
5. Add unit tests in `tests/`.

## Adding a new notification channel

Add a `send_<channel>()` function to `app/services/notification_service.py`
following the existing `send_email` / `send_telegram` / `send_slack` pattern
(return `(success: bool, error: str | None)`, never raise), then call it from
`dispatch_alert_notifications()`.

## Database migrations

This project uses Alembic with autogenerate support wired to the SQLAlchemy
models (`migrations/env.py` imports `app.models` so all tables are detected).

```bash
# After changing/adding a model:
alembic revision --autogenerate -m "describe your change"

# Review the generated file in migrations/versions/ before applying!
alembic upgrade head

# Roll back one revision:
alembic downgrade -1
```

## Authentication & RBAC

- Passwords are hashed with bcrypt via Passlib (`app/utils/security.py`).
- Access tokens are JWTs signed with `SECRET_KEY` (HS256), valid for
  `ACCESS_TOKEN_EXPIRE_MINUTES` (default 60).
- The HTML UI stores the JWT in an `httponly` cookie (`access_token`); the
  REST API accepts it via the standard `Authorization: Bearer <token>` header.
  `app/dependencies.py::get_current_user` accepts either.
- Three seeded roles: `admin`, `analyst`, `viewer`. Use
  `Depends(require_admin)` or `Depends(require_role("admin", "analyst"))` on
  any route that needs to restrict access. `User.is_superuser` always bypasses
  role checks.

## Running tests

```bash
pytest tests/ -v
```

Each test gets an isolated, temporary SQLite database via the `client`
fixture in `tests/conftest.py` — tests never touch your real
`threatshield.db` or a shared PostgreSQL instance.

## Code style

The codebase follows PEP 8. `flake8` is run in CI (see
`.github/workflows/ci.yml`) with `--exit-zero`, so it reports issues without
failing the build — tighten this once the codebase is stable if you want
enforced linting.

## Extending the frontend

Templates extend `app/templates/base.html`, which loads Bootstrap 5 and
Chart.js from CDN and includes a shared navbar. Add new pages by creating a
template that extends `base.html` and a route in the relevant
`app/routers/*.py` file that returns
`templates.TemplateResponse("your_template.html", {...})`.
