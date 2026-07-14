"""Tests for report generation (PDF/CSV/Excel) via the API."""
import os

import pytest


def _get_token(client, username="reportuser"):
    client.post(
        "/api/auth/register",
        json={"username": username, "email": f"{username}@example.com", "password": "TestPassword123"},
    )
    response = client.post("/api/auth/login", data={"username": username, "password": "TestPassword123"})
    return response.json()["access_token"]


def test_generate_org_wide_pdf_report(client):
    token = _get_token(client)
    headers = {"Authorization": f"Bearer {token}"}
    response = client.post("/api/reports", json={"asset_id": None, "report_type": "pdf"}, headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["report_type"] == "pdf"
    assert os.path.exists(body["file_path"])


def test_generate_csv_report(client):
    token = _get_token(client)
    headers = {"Authorization": f"Bearer {token}"}
    response = client.post("/api/reports", json={"asset_id": None, "report_type": "csv"}, headers=headers)
    assert response.status_code == 200
    assert response.json()["report_type"] == "csv"


def test_generate_excel_report(client):
    token = _get_token(client)
    headers = {"Authorization": f"Bearer {token}"}
    response = client.post("/api/reports", json={"asset_id": None, "report_type": "xlsx"}, headers=headers)
    assert response.status_code == 200
    assert response.json()["report_type"] == "xlsx"


def test_invalid_report_type_rejected(client):
    token = _get_token(client)
    headers = {"Authorization": f"Bearer {token}"}
    # The service layer raises ValueError for unsupported types; the deployed app's
    # global exception handler turns this into a 500 JSON response, but the test
    # client re-raises unhandled server exceptions by default, so we assert here.
    with pytest.raises(ValueError):
        client.post("/api/reports", json={"asset_id": None, "report_type": "docx"}, headers=headers)
