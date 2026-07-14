"""
Shared pytest fixtures.

Each test gets a fresh, isolated SQLite database (file-based, unique per
test) so tests never interfere with each other or with any real
development database.
"""
import os
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ["SCHEDULER_ENABLED"] = "false"  # keep tests fast and deterministic


@pytest.fixture()
def test_db_url(tmp_path):
    db_file = tmp_path / f"test_{uuid.uuid4().hex}.db"
    return f"sqlite:///{db_file}"


@pytest.fixture()
def client(test_db_url, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", test_db_url)

    # Reset cached settings so the new DATABASE_URL takes effect
    from app.config import get_settings

    get_settings.cache_clear()

    import app.database as database_module

    engine = create_engine(test_db_url, connect_args={"check_same_thread": False}, future=True)
    database_module.engine = engine
    database_module.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, future=True)

    from app.main import app

    with TestClient(app) as test_client:
        yield test_client
