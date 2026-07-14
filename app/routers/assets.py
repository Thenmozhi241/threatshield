"""Asset management routes: list, add, view details, delete (HTML + JSON API)."""
from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user
from app.models.alert import Alert
from app.models.asset import Asset, AssetType
from app.models.dns_record import DNSRecord
from app.models.port_scan_result import PortScanResult
from app.models.scan_result import ScanResult
from app.models.ssl_result import SSLResult
from app.models.threat_score import ThreatScore
from app.models.user import User
from app.models.whois_result import WhoisResult
from app.schemas.asset import AssetCreate, AssetOut
from app.services import abuseipdb_service
from app.services.audit_service import log_action
from app.services.reputation_service import get_blacklist_summary, get_delisting_url
from app.utils.validators import is_valid_asset_target, is_valid_domain, sanitize_text

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/assets", tags=["ui"])
def list_assets_page(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    assets = db.query(Asset).order_by(Asset.created_at.desc()).all()
    rows = []
    for asset in assets:
        summary = get_blacklist_summary(db, asset.id)
        rows.append({"asset": asset, **summary})
    return templates.TemplateResponse("assets.html", {"request": request, "user": user, "rows": rows})


@router.get("/assets/add", tags=["ui"])
def add_asset_page(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    asset_types = db.query(AssetType).all()
    return templates.TemplateResponse("add_asset.html", {"request": request, "user": user, "asset_types": asset_types})


@router.post("/assets/add", tags=["ui"])
def add_asset_submit(
    request: Request,
    name: str = Form(...),
    asset_type_id: int = Form(...),
    description: str = Form(""),
    tags: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    clean_name = sanitize_text(name, max_length=255).strip()
    if not is_valid_asset_target(clean_name):
        asset_types = db.query(AssetType).all()
        return templates.TemplateResponse(
            "add_asset.html",
            {
                "request": request,
                "user": user,
                "asset_types": asset_types,
                "error": "Please enter a valid domain name or IP address.",
            },
            status_code=400,
        )

    asset = Asset(
        name=clean_name,
        asset_type_id=asset_type_id,
        owner_id=user.id,
        description=sanitize_text(description, 1000),
        tags=sanitize_text(tags, 255),
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    log_action(db, user.id, "create_asset", resource=f"asset:{asset.id}", details=clean_name)
    return RedirectResponse(url=f"/assets/{asset.id}", status_code=status.HTTP_302_FOUND)


def _build_asset_detail_context(asset_id: int, db: Session, user: User) -> dict:
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    is_domain = is_valid_domain(asset.name)

    dns_records = db.query(DNSRecord).filter(DNSRecord.asset_id == asset_id).order_by(DNSRecord.checked_at.desc()).limit(50).all()
    whois_result = db.query(WhoisResult).filter(WhoisResult.asset_id == asset_id).order_by(WhoisResult.checked_at.desc()).first()
    ssl_result = db.query(SSLResult).filter(SSLResult.asset_id == asset_id).order_by(SSLResult.checked_at.desc()).first()
    port_results = db.query(PortScanResult).filter(PortScanResult.asset_id == asset_id).order_by(PortScanResult.checked_at.desc()).limit(50).all()
    threat_score = db.query(ThreatScore).filter(ThreatScore.asset_id == asset_id).order_by(ThreatScore.calculated_at.desc()).first()
    scans = db.query(ScanResult).filter(ScanResult.asset_id == asset_id).order_by(ScanResult.started_at.desc()).limit(20).all()
    alerts = db.query(Alert).filter(Alert.asset_id == asset_id).order_by(Alert.created_at.desc()).limit(20).all()

    blacklist_summary = get_blacklist_summary(db, asset_id)
    delisting_links = {row.provider: get_delisting_url(row.provider) for row in blacklist_summary["rows"]}

    # "Is server up" derived from the most recent port scan: reachable if 80 or 443 responded open.
    server_up = None
    if port_results:
        latest_checked_at = port_results[0].checked_at
        latest_batch = [p for p in port_results if p.checked_at == latest_checked_at]
        server_up = any(p.is_open and p.port in (80, 443) for p in latest_batch)

    return {
        "user": user,
        "asset": asset,
        "is_domain": is_domain,
        "dns_records": dns_records,
        "whois_result": whois_result,
        "ssl_result": ssl_result,
        "port_results": port_results,
        "threat_score": threat_score,
        "scans": scans,
        "alerts": alerts,
        "blacklist_summary": blacklist_summary,
        "delisting_links": delisting_links,
        "server_up": server_up,
        "abuseipdb_configured": abuseipdb_service.is_configured(),
        "abuseipdb_result": None,
    }


@router.get("/assets/{asset_id}", tags=["ui"])
def asset_details_page(
    asset_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)
):
    context = _build_asset_detail_context(asset_id, db, user)
    context["request"] = request
    return templates.TemplateResponse("asset_details.html", context)


@router.get("/assets/{asset_id}/abuseipdb-check", tags=["ui"])
def asset_abuseipdb_check(asset_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Run an on-demand AbuseIPDB check for an asset and re-render its detail page with the result."""
    context = _build_asset_detail_context(asset_id, db, user)
    context["request"] = request

    if abuseipdb_service.is_configured():
        import socket

        asset = context["asset"]
        try:
            ip = asset.name if not is_valid_domain(asset.name) else socket.gethostbyname(asset.name)
            context["abuseipdb_result"] = abuseipdb_service.check_abuseipdb(ip)
        except socket.gaierror:
            context["abuseipdb_result"] = {"configured": True, "error": "Could not resolve this asset to an IP address."}

    return templates.TemplateResponse("asset_details.html", context)


@router.post("/assets/{asset_id}/delete", tags=["ui"])
def delete_asset(asset_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    db.delete(asset)
    db.commit()
    log_action(db, user.id, "delete_asset", resource=f"asset:{asset_id}")
    return RedirectResponse(url="/assets", status_code=status.HTTP_302_FOUND)


# ---------- JSON REST API ----------

@router.post("/api/assets", response_model=AssetOut, tags=["assets"])
def api_create_asset(payload: AssetCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not is_valid_asset_target(payload.name):
        raise HTTPException(status_code=400, detail="Invalid domain or IP address")
    asset = Asset(
        name=payload.name,
        asset_type_id=payload.asset_type_id,
        owner_id=user.id,
        description=payload.description,
        tags=payload.tags,
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    log_action(db, user.id, "create_asset", resource=f"asset:{asset.id}")
    return asset


@router.get("/api/assets", response_model=list[AssetOut], tags=["assets"])
def api_list_assets(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return db.query(Asset).order_by(Asset.created_at.desc()).all()


@router.get("/api/assets/{asset_id}", response_model=AssetOut, tags=["assets"])
def api_get_asset(asset_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@router.delete("/api/assets/{asset_id}", tags=["assets"])
def api_delete_asset(asset_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    db.delete(asset)
    db.commit()
    log_action(db, user.id, "delete_asset", resource=f"asset:{asset_id}")
    return {"detail": "Asset deleted"}
