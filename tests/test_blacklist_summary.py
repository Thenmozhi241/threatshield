"""
Regression test: all BlacklistResult rows written by a single scan must
share one timestamp, so get_blacklist_summary() groups the whole batch
together instead of only matching whichever row happens to have the
latest (sub-second-distinct) checked_at value.
"""
from app.database import Base
from app.models.asset import Asset, AssetType
from app.models.role import Role
from app.models.user import User
from app.services.reputation_service import get_blacklist_summary
from app.services.scan_orchestrator import run_full_scan
from app.utils.security import hash_password


def _make_asset(db, name="8.8.8.8"):
    role = db.query(Role).filter(Role.name == "admin").first()
    if not role:
        role = Role(name="admin", description="test")
        db.add(role)
        db.commit()
        db.refresh(role)

    user = User(username="scantest", email="scantest@example.com", hashed_password=hash_password("x"), role_id=role.id)
    db.add(user)
    db.commit()
    db.refresh(user)

    asset_type = db.query(AssetType).filter(AssetType.name == "ip").first()
    if not asset_type:
        asset_type = AssetType(name="ip", description="test")
        db.add(asset_type)
        db.commit()
        db.refresh(asset_type)

    asset = Asset(name=name, asset_type_id=asset_type.id, owner_id=user.id)
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


def test_blacklist_results_share_one_batch_timestamp(client):
    # `client` fixture wires up an isolated SQLite DB via app.database.SessionLocal
    from app.database import SessionLocal

    db = SessionLocal()
    try:
        asset = _make_asset(db)
        run_full_scan(db, asset)

        summary = get_blacklist_summary(db, asset.id)
        # All ~28 configured DNSBL providers should appear in the same batch,
        # not just one or two due to a timestamp mismatch.
        assert summary["total_count"] >= 20
        assert len(summary["rows"]) == summary["total_count"]
    finally:
        db.close()
