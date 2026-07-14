# Installation Guide

## Prerequisites

- Python 3.12+
- pip
- (Optional, for production) PostgreSQL 14+
- (Optional) Docker & Docker Compose

## 1. Clone the project

```bash
git clone <your-fork-url> threatshield
cd threatshield
```

## 2. Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
```

## 3. Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

## 4. Configure environment variables

```bash
cp .env.example .env
```

Edit `.env` and set at minimum:
- `SECRET_KEY` — a long random string (used to sign JWTs)
- `DATABASE_URL` — leave as the default SQLite URL for local dev, or point at PostgreSQL for production
- Notification credentials (SMTP / Telegram / Slack) if you want live alerts — all are optional and disabled by default

## 5. Run database migrations

```bash
alembic upgrade head
```

This creates all 16 tables (users, roles, assets, scan results, alerts, etc.)
using the SQLite (or PostgreSQL, if configured) database at `DATABASE_URL`.

## 6. (Optional) Load sample data

```bash
python seed_data.py
```

Creates sample users (`admin` / `AdminPass123`, `analyst1` / `AnalystPass123`,
`viewer1` / `ViewerPass123`), four sample assets, threat scores, a scan
history entry, and one sample alert, so the UI has data to show immediately.

## 7. Start PostgreSQL (production only)

If you're using PostgreSQL instead of SQLite:

```bash
# via Docker
docker run -d --name threatshield-postgres \
  -e POSTGRES_USER=threatshield -e POSTGRES_PASSWORD=threatshield -e POSTGRES_DB=threatshield \
  -p 5432:5432 postgres:16-alpine
```

Then set `DATABASE_URL=postgresql://threatshield:threatshield@localhost:5432/threatshield`
in `.env` and re-run `alembic upgrade head`.

## 8. Run the FastAPI server

```bash
uvicorn app.main:app --reload
```

Visit http://localhost:8000/login. The background scheduler (automatic scans)
starts automatically with the app — see step 9 for details.

## 9. Scheduled jobs

The scheduler runs in-process with the app (via APScheduler) — no separate
process is required. It's controlled by two `.env` variables:

```bash
SCHEDULER_ENABLED=true
SCAN_INTERVAL_HOURS=24
```

## 10. Run with Docker Compose (full stack: app + PostgreSQL + Nginx + Prometheus + Grafana)

```bash
docker compose up --build
```

This starts:
- the app on port 8000 (also reachable via Nginx on port 80)
- PostgreSQL on port 5432
- Prometheus on port 9090
- Grafana on port 3000 (login: `admin` / `admin`, see `GF_SECURITY_ADMIN_PASSWORD` in `docker-compose.yml`)

Migrations run automatically on container startup (`alembic upgrade head`
before `uvicorn` starts, per the `app` service `command` in
`docker-compose.yml`).

## 11. Access the application

- Web UI: http://localhost:8000 (or http://localhost with Docker/Nginx)
- REST API docs (Swagger UI): http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc
- Grafana: http://localhost:3000
- Prometheus: http://localhost:9090

## 12. Run tests

```bash
pytest tests/ -v
```

All 26 tests use isolated, per-test SQLite databases and don't touch your
development database.

## 13. Build a production image

```bash
docker build -f docker/Dockerfile -t threatshield:latest .
docker run -d -p 8000:8000 --env-file .env threatshield:latest
```
