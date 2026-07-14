"""
ThreatShield — Cyber Threat Intelligence & Asset Monitoring Platform.

Main FastAPI application: wires up middleware, routers, static files,
templates, exception handlers, and the background scheduler.
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.config import settings
from app.database import init_db
from app.routers import alerts, api, assets, auth, dashboard, reports, scans, settings as settings_router, tools, users
from app.scheduler.scheduler import shutdown_scheduler, start_scheduler
from app.utils.logger import logger

limiter = Limiter(key_func=get_remote_address, default_limits=[f"{settings.rate_limit_per_minute}/minute"])


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting %s (%s environment)...", settings.app_name, settings.app_env)
    init_db()
    _seed_lookup_data()
    start_scheduler()
    yield
    shutdown_scheduler()
    logger.info("Shutdown complete.")


app = FastAPI(
    title="ThreatShield API",
    description="Cyber Threat Intelligence & Asset Monitoring Platform",
    version="1.0.0",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if settings.app_env == "production":
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response


app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

# --- Routers ---
app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(assets.router)
app.include_router(scans.router)
app.include_router(alerts.router)
app.include_router(reports.router)
app.include_router(users.router)
app.include_router(settings_router.router)
app.include_router(tools.router)
app.include_router(api.router)


@app.get("/", tags=["ui"])
def root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/", tags=["ui"])
@limiter.limit("10/minute")
def root_quick_check(request: Request, target: str = Form(...)):
    from app.services import reputation_service
    from app.utils.validators import is_valid_asset_target, sanitize_text

    clean_target = sanitize_text(target, 255).strip()
    error = None
    result = None
    if not is_valid_asset_target(clean_target):
        error = "Please enter a valid domain name or IP address."
    else:
        result = reputation_service.check_reputation(clean_target)
    return templates.TemplateResponse(
        "index.html", {"request": request, "target": clean_target, "result": result, "error": error}
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code == 404 and "text/html" in request.headers.get("accept", ""):
        return templates.TemplateResponse("errors/404.html", {"request": request}, status_code=404)
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception: %s", exc)
    if "text/html" in request.headers.get("accept", ""):
        return templates.TemplateResponse("errors/500.html", {"request": request}, status_code=500)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


def _seed_lookup_data() -> None:
    """Ensure baseline roles and asset types exist (idempotent)."""
    from app.database import SessionLocal
    from app.models.asset import AssetType
    from app.models.role import Role

    db = SessionLocal()
    try:
        default_roles = [
            ("admin", "Full administrative access"),
            ("analyst", "Can manage assets, run scans, and resolve alerts"),
            ("viewer", "Read-only access"),
        ]
        for name, description in default_roles:
            if not db.query(Role).filter(Role.name == name).first():
                db.add(Role(name=name, description=description))

        default_types = [
            ("domain", "A fully qualified domain name"),
            ("ip", "An IPv4 or IPv6 address"),
            ("url", "A specific URL/endpoint"),
        ]
        for name, description in default_types:
            if not db.query(AssetType).filter(AssetType.name == name).first():
                db.add(AssetType(name=name, description=description))

        db.commit()
    finally:
        db.close()
