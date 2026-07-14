# Deployment Guide

## Recommended production topology

```
Internet → Nginx (TLS termination, port 443) → Uvicorn workers (FastAPI app) → PostgreSQL
                                                                              → Prometheus/Grafana (internal only)
```

## Docker Compose deployment

```bash
cp .env.example .env
# edit .env: set a strong SECRET_KEY, real SMTP/Telegram/Slack credentials if desired,
# and APP_ENV=production

docker compose up -d --build
```

The `app` service automatically runs `alembic upgrade head` before starting
Uvicorn (see the `command` in `docker-compose.yml`), so schema migrations are
applied on every deploy.

## TLS / HTTPS

The bundled `nginx/nginx.conf` listens on port 80 only, suitable for
local/demo use or when TLS is terminated further upstream (e.g. a cloud load
balancer). For a standalone production deployment, put a TLS-terminating
proxy (Nginx with Let's Encrypt/Certbot, or a managed load balancer) in front
of the `nginx` service, or extend `nginx.conf` with a `listen 443 ssl;`
server block and your certificate paths.

## Environment variables checklist for production

| Variable | Recommendation |
|---|---|
| `APP_ENV` | `production` |
| `DEBUG` | `false` |
| `SECRET_KEY` | Long, random, unique per environment (`openssl rand -hex 32`) |
| `DATABASE_URL` | PostgreSQL connection string, not SQLite |
| `ALLOWED_ORIGINS` | Your real frontend origin(s), not `*` |
| `EMAIL_ALERTS_ENABLED` / `TELEGRAM_ALERTS_ENABLED` / `SLACK_ALERTS_ENABLED` | Enable the channels you actually use, with real credentials |
| `SCHEDULER_ENABLED` | `true` (recommended) |
| `RATE_LIMIT_PER_MINUTE` | Tune to your expected traffic |

## Scaling

- The app is stateless aside from the database, so you can run multiple
  Uvicorn/container replicas behind Nginx or a load balancer.
- **Important**: only run the APScheduler background job (`SCHEDULER_ENABLED=true`)
  on a single replica to avoid duplicate scans; set `SCHEDULER_ENABLED=false`
  on any additional replicas, or extract the scheduler into its own
  single-instance worker process/container.
- PostgreSQL should be a managed instance or a properly backed-up container
  volume in production — the bundled `docker-compose.yml` Postgres service
  uses a local named volume, which is fine for demos but should be replaced
  with a managed database or proper backup strategy for real use.

## Backups

- **Database**: use `pg_dump`/`pg_restore` (PostgreSQL) on a schedule.
- **Generated reports**: the `generated_reports/` directory (mounted as a
  volume in `docker-compose.yml`) contains historical report files; back it
  up alongside the database if you need long-term report retention.

## Monitoring

Prometheus and Grafana are included in `docker-compose.yml` for
infrastructure-level monitoring. Out of the box, Prometheus can scrape
`/api/health`; for full HTTP request metrics, add
[`prometheus-fastapi-instrumentator`](https://github.com/trallnag/prometheus-fastapi-instrumentator)
and expose a `/metrics` endpoint in `app/main.py` (the provided
`monitoring/prometheus.yml` already targets `/metrics` on the `app` service,
ready for this addition).

## Zero-downtime deploys

For simple setups, `docker compose up -d --build` will recreate the `app`
container with a brief interruption. For true zero-downtime deploys, put
multiple `app` replicas behind Nginx (or a cloud load balancer) and roll them
one at a time.
