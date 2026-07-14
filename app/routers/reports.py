"""Report routes: generate PDF/CSV/Excel reports and list/download them."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette import status

from app.database import get_db
from app.dependencies import get_current_user
from app.models.asset import Asset
from app.models.report import Report
from app.models.user import User
from app.schemas.report import ReportOut, ReportRequest
from app.services.audit_service import log_action
from app.services.report_service import generate_report

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


def _build_output_name(asset_id: int | None) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    scope = f"asset_{asset_id}" if asset_id else "org_wide"
    return f"report_{scope}_{ts}"


@router.get("/reports", tags=["ui"])
def reports_page(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    reports = db.query(Report).order_by(Report.created_at.desc()).limit(100).all()
    assets = db.query(Asset).all()
    return templates.TemplateResponse(
        "reports.html", {"request": request, "user": user, "reports": reports, "assets": assets}
    )


@router.post("/reports/generate", tags=["ui"])
def generate_report_ui(
    request: Request,
    asset_id: str = Form(""),
    report_type: str = Form("pdf"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    parsed_asset_id = int(asset_id) if asset_id else None
    output_name = _build_output_name(parsed_asset_id)
    file_path = generate_report(db, parsed_asset_id, report_type, output_name)

    title = f"{'Org-wide' if not parsed_asset_id else 'Asset'} report ({report_type.upper()})"
    report = Report(
        generated_by=user.id,
        asset_id=parsed_asset_id,
        report_type=report_type,
        title=title,
        file_path=file_path,
    )
    db.add(report)
    db.commit()
    log_action(db, user.id, "generate_report", resource=f"report:{report.id}")
    return RedirectResponse(url="/reports", status_code=status.HTTP_302_FOUND)


@router.get("/reports/{report_id}/download", tags=["ui"])
def download_report(report_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(report.file_path, filename=f"{report.title}.{report.report_type}")


@router.post("/api/reports", response_model=ReportOut, tags=["reports"])
def api_generate_report(payload: ReportRequest, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    output_name = _build_output_name(payload.asset_id)
    file_path = generate_report(db, payload.asset_id, payload.report_type, output_name)
    title = f"{'Org-wide' if not payload.asset_id else 'Asset'} report ({payload.report_type.upper()})"
    report = Report(
        generated_by=user.id,
        asset_id=payload.asset_id,
        report_type=payload.report_type,
        title=title,
        file_path=file_path,
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    log_action(db, user.id, "generate_report", resource=f"report:{report.id}")
    return report


@router.get("/api/reports", response_model=list[ReportOut], tags=["reports"])
def api_list_reports(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return db.query(Report).order_by(Report.created_at.desc()).all()
