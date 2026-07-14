"""
Seed the database with sample data for demo/development purposes.

Usage:
    python seed_data.py

This creates:
- Roles: admin, analyst, viewer (idempotent)
- Asset types: domain, ip, url (idempotent)
- Sample users (admin, analyst, viewer accounts)
- Sample assets, a threat score, an alert, and a scan-history record per asset

NOTE: This does not run live scans (no network calls) — it inserts
representative rows so the UI has something to show immediately. Use the
"Run Scan Now" button, or the scheduler, to generate real, current data.
"""
import json
from datetime import datetime, timedelta, timezone

from app.database import Base, SessionLocal, engine
from app.models.alert import Alert
from app.models.asset import Asset, AssetType
from app.models.report import Report
from app.models.role import Role
from app.models.scan_result import ScanResult
from app.models.threat_score import ThreatScore
from app.models.user import User
from app.utils.security import hash_password

Base.metadata.create_all(bind=engine)

db = SessionLocal()

try:
    # --- Roles ---
    roles = {}
    for name, description in [
        ("admin", "Full administrative access"),
        ("analyst", "Can manage assets, run scans, and resolve alerts"),
        ("viewer", "Read-only access"),
    ]:
        role = db.query(Role).filter(Role.name == name).first()
        if not role:
            role = Role(name=name, description=description)
            db.add(role)
            db.commit()
            db.refresh(role)
        roles[name] = role

    # --- Asset types ---
    types = {}
    for name, description in [
        ("domain", "A fully qualified domain name"),
        ("ip", "An IPv4 or IPv6 address"),
        ("url", "A specific URL/endpoint"),
    ]:
        atype = db.query(AssetType).filter(AssetType.name == name).first()
        if not atype:
            atype = AssetType(name=name, description=description)
            db.add(atype)
            db.commit()
            db.refresh(atype)
        types[name] = atype

    # --- Sample users ---
    sample_users = [
        ("admin", "admin@threatshield.local", "System Administrator", "AdminPass123", roles["admin"], True),
        ("analyst1", "analyst1@threatshield.local", "Security Analyst", "AnalystPass123", roles["analyst"], False),
        ("viewer1", "viewer1@threatshield.local", "Read Only Viewer", "ViewerPass123", roles["viewer"], False),
    ]
    created_users = {}
    for username, email, full_name, password, role, is_super in sample_users:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            user = User(
                username=username,
                email=email,
                full_name=full_name,
                hashed_password=hash_password(password),
                role_id=role.id,
                is_superuser=is_super,
                is_active=True,
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        created_users[username] = user

    admin_user = created_users["admin"]

    # --- Sample assets ---
    sample_assets = [
        ("example.com", "domain", "Primary corporate website", "production,web"),
        ("api.example.com", "domain", "Public REST API endpoint", "production,api"),
        ("203.0.113.10", "ip", "Edge load balancer (documentation range)", "production,network"),
        ("staging.example.com", "domain", "Staging environment", "staging"),
    ]
    created_assets = []
    for name, type_name, description, tags in sample_assets:
        asset = db.query(Asset).filter(Asset.name == name).first()
        if not asset:
            asset = Asset(
                name=name,
                asset_type_id=types[type_name].id,
                owner_id=admin_user.id,
                description=description,
                tags=tags,
            )
            db.add(asset)
            db.commit()
            db.refresh(asset)
        created_assets.append(asset)

    # --- Sample threat scores, scans, alerts, and reports ---
    sample_scores = [12.5, 34.0, 61.5, 8.0]
    sample_levels = ["low", "medium", "high", "low"]

    for asset, score, level in zip(created_assets, sample_scores, sample_levels):
        if not db.query(ThreatScore).filter(ThreatScore.asset_id == asset.id).first():
            db.add(
                ThreatScore(
                    asset_id=asset.id,
                    score=score,
                    risk_level=level,
                    factors=json.dumps({"sample_data": True}),
                    calculated_at=datetime.now(timezone.utc) - timedelta(hours=1),
                )
            )

        if not db.query(ScanResult).filter(ScanResult.asset_id == asset.id).first():
            db.add(
                ScanResult(
                    asset_id=asset.id,
                    scan_type="full",
                    status="completed",
                    summary=f"Risk score: {score} ({level})",
                    findings_count=3,
                    started_at=datetime.now(timezone.utc) - timedelta(hours=1, minutes=5),
                    finished_at=datetime.now(timezone.utc) - timedelta(hours=1),
                )
            )

    # One sample alert on the high-risk asset
    high_risk_asset = created_assets[2]
    if not db.query(Alert).filter(Alert.asset_id == high_risk_asset.id).first():
        db.add(
            Alert(
                asset_id=high_risk_asset.id,
                severity="warning",
                category="port_open",
                title=f"Sensitive port 3389 open on {high_risk_asset.name}",
                message="Port 3389 (RDP) is open and exposed to the internet.",
            )
        )

    # One sample report record (metadata only; no file generated here)
    if not db.query(Report).filter(Report.title == "Sample Org-wide Report (PDF)").first():
        db.add(
            Report(
                generated_by=admin_user.id,
                asset_id=None,
                report_type="pdf",
                title="Sample Org-wide Report (PDF)",
                file_path="generated_reports/sample_report.pdf",
            )
        )

    db.commit()

    print("Seed data created successfully:")
    print(f"  Users:  admin/AdminPass123, analyst1/AnalystPass123, viewer1/ViewerPass123")
    print(f"  Assets: {', '.join(a.name for a in created_assets)}")
    print("Run the app and log in with the admin account to explore the seeded data.")

finally:
    db.close()
