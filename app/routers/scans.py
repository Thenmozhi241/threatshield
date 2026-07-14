"""Scan routes: trigger a scan for an asset, view scan history/results."""
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette import status

from app.database import get_db
from app.dependencies import get_current_user
from app.models.asset import Asset
from app.models.scan_result import ScanResult
from app.models.user import User
from app.schemas.scan import ScanRequest, ScanResultOut
from app.services.audit_service import log_action
from app.services.scan_orchestrator import run_full_scan

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/scans", tags=["ui"])
def scan_results_page(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    scans = db.query(ScanResult).order_by(ScanResult.started_at.desc()).limit(100).all()
    return templates.TemplateResponse("scan_results.html", {"request": request, "user": user, "scans": scans})


@router.post("/assets/{asset_id}/scan", tags=["ui"])
def trigger_scan_ui(asset_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    run_full_scan(db, asset)
    log_action(db, user.id, "run_scan", resource=f"asset:{asset_id}")
    return RedirectResponse(url=f"/assets/{asset_id}", status_code=status.HTTP_302_FOUND)


@router.post("/api/scans", response_model=ScanResultOut, tags=["scans"])
def api_trigger_scan(payload: ScanRequest, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    asset = db.query(Asset).filter(Asset.id == payload.asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    scan = run_full_scan(db, asset)
    log_action(db, user.id, "run_scan", resource=f"asset:{asset.id}")
    return scan


@router.get("/api/scans", response_model=list[ScanResultOut], tags=["scans"])
def api_list_scans(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return db.query(ScanResult).order_by(ScanResult.started_at.desc()).limit(200).all()


@router.get("/api/scans/{scan_id}", response_model=ScanResultOut, tags=["scans"])
def api_get_scan(scan_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan
