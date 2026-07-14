"""
Report generation service. Produces PDF (reportlab), CSV, and Excel
(openpyxl) reports summarizing asset threat posture, findings, and
recommendations.
"""
from __future__ import annotations

import csv
import os
from datetime import datetime, timezone

from openpyxl import Workbook
from openpyxl.styles import Font
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.asset import Asset
from app.models.threat_score import ThreatScore

REPORTS_DIR = "generated_reports"
os.makedirs(REPORTS_DIR, exist_ok=True)


def _gather_report_data(db: Session, asset_id: int | None) -> dict:
    if asset_id:
        assets = db.query(Asset).filter(Asset.id == asset_id).all()
    else:
        assets = db.query(Asset).all()

    rows = []
    for asset in assets:
        latest_score = (
            db.query(ThreatScore)
            .filter(ThreatScore.asset_id == asset.id)
            .order_by(ThreatScore.calculated_at.desc())
            .first()
        )
        open_alerts = (
            db.query(Alert)
            .filter(Alert.asset_id == asset.id, Alert.is_resolved.is_(False))
            .all()
        )
        rows.append(
            {
                "asset": asset,
                "score": latest_score.score if latest_score else None,
                "risk_level": latest_score.risk_level if latest_score else "unknown",
                "open_alerts": open_alerts,
            }
        )
    return {"rows": rows, "generated_at": datetime.now(timezone.utc)}


def _recommendations_for(row: dict) -> list[str]:
    recs = []
    for alert in row["open_alerts"]:
        if alert.category == "ssl_expiry":
            recs.append("Renew the SSL/TLS certificate before expiry.")
        elif alert.category == "domain_expiry":
            recs.append("Renew the domain registration promptly.")
        elif alert.category == "port_open":
            recs.append("Restrict or firewall the exposed service port.")
        elif alert.category == "reputation":
            recs.append("Investigate and remediate the cause of blacklisting, then request delisting.")
        elif alert.category == "threat_score":
            recs.append("Review all findings for this asset and prioritize remediation.")
    return list(dict.fromkeys(recs)) or ["No immediate action required."]


def generate_pdf_report(db: Session, asset_id: int | None, output_name: str) -> str:
    data = _gather_report_data(db, asset_id)
    file_path = os.path.join(REPORTS_DIR, f"{output_name}.pdf")

    doc = SimpleDocTemplate(file_path, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = [
        Paragraph("ThreatShield Threat Intelligence Report", styles["Title"]),
        Paragraph(f"Generated: {data['generated_at'].strftime('%Y-%m-%d %H:%M UTC')}", styles["Normal"]),
        Spacer(1, 0.5 * cm),
        Paragraph("Executive Summary", styles["Heading2"]),
        Paragraph(
            f"This report covers {len(data['rows'])} monitored asset(s). "
            "Findings, current risk scores, and remediation recommendations are detailed below.",
            styles["Normal"],
        ),
        Spacer(1, 0.5 * cm),
    ]

    for row in data["rows"]:
        asset = row["asset"]
        elements.append(Paragraph(f"Asset: {asset.name}", styles["Heading3"]))
        elements.append(
            Paragraph(f"Risk Score: {row['score']} — Risk Level: {row['risk_level'].upper()}", styles["Normal"])
        )

        table_data = [["Severity", "Category", "Title"]]
        for alert in row["open_alerts"]:
            table_data.append([alert.severity, alert.category, alert.title])
        if len(table_data) == 1:
            table_data.append(["-", "-", "No open findings"])

        table = Table(table_data, colWidths=[3 * cm, 4 * cm, 9 * cm])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                ]
            )
        )
        elements.append(table)
        elements.append(Spacer(1, 0.3 * cm))

        elements.append(Paragraph("Recommendations:", styles["Heading4"]))
        for rec in _recommendations_for(row):
            elements.append(Paragraph(f"• {rec}", styles["Normal"]))
        elements.append(Spacer(1, 0.6 * cm))

    doc.build(elements)
    return file_path


def generate_csv_report(db: Session, asset_id: int | None, output_name: str) -> str:
    data = _gather_report_data(db, asset_id)
    file_path = os.path.join(REPORTS_DIR, f"{output_name}.csv")

    with open(file_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Asset", "Risk Score", "Risk Level", "Open Alert Severity", "Open Alert Category", "Open Alert Title"])
        for row in data["rows"]:
            asset = row["asset"]
            if not row["open_alerts"]:
                writer.writerow([asset.name, row["score"], row["risk_level"], "-", "-", "No open findings"])
            for alert in row["open_alerts"]:
                writer.writerow([asset.name, row["score"], row["risk_level"], alert.severity, alert.category, alert.title])

    return file_path


def generate_excel_report(db: Session, asset_id: int | None, output_name: str) -> str:
    data = _gather_report_data(db, asset_id)
    file_path = os.path.join(REPORTS_DIR, f"{output_name}.xlsx")

    wb = Workbook()
    ws = wb.active
    ws.title = "Threat Report"

    headers = ["Asset", "Risk Score", "Risk Level", "Alert Severity", "Alert Category", "Alert Title"]
    ws.append(headers)
    for cell in ws[1]:
        cell.font = Font(bold=True)

    for row in data["rows"]:
        asset = row["asset"]
        if not row["open_alerts"]:
            ws.append([asset.name, row["score"], row["risk_level"], "-", "-", "No open findings"])
        for alert in row["open_alerts"]:
            ws.append([asset.name, row["score"], row["risk_level"], alert.severity, alert.category, alert.title])

    wb.save(file_path)
    return file_path


def generate_report(db: Session, asset_id: int | None, report_type: str, output_name: str) -> str:
    if report_type == "pdf":
        return generate_pdf_report(db, asset_id, output_name)
    if report_type == "csv":
        return generate_csv_report(db, asset_id, output_name)
    if report_type == "xlsx":
        return generate_excel_report(db, asset_id, output_name)
    raise ValueError(f"Unsupported report type: {report_type}")
