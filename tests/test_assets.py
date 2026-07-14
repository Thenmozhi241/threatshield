"""Tests for asset CRUD endpoints."""


def _get_token(client, username="assetuser"):
    client.post(
        "/api/auth/register",
        json={"username": username, "email": f"{username}@example.com", "password": "TestPassword123"},
    )
    response = client.post("/api/auth/login", data={"username": username, "password": "TestPassword123"})
    return response.json()["access_token"]


def test_create_asset_requires_auth(client):
    response = client.post("/api/assets", json={"name": "example.com", "asset_type_id": 1})
    assert response.status_code == 401


def test_create_valid_domain_asset(client):
    token = _get_token(client)
    headers = {"Authorization": f"Bearer {token}"}
    response = client.post(
        "/api/assets",
        json={"name": "example.com", "asset_type_id": 1, "description": "test", "tags": "prod"},
        headers=headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["name"] == "example.com"


def test_create_invalid_target_rejected(client):
    token = _get_token(client)
    headers = {"Authorization": f"Bearer {token}"}
    response = client.post(
        "/api/assets",
        json={"name": "not a valid domain!!", "asset_type_id": 1},
        headers=headers,
    )
    assert response.status_code == 400


def test_list_and_get_asset(client):
    token = _get_token(client)
    headers = {"Authorization": f"Bearer {token}"}
    create_resp = client.post(
        "/api/assets", json={"name": "192.0.2.10", "asset_type_id": 2}, headers=headers
    )
    asset_id = create_resp.json()["id"]

    list_resp = client.get("/api/assets", headers=headers)
    assert list_resp.status_code == 200
    assert any(a["id"] == asset_id for a in list_resp.json())

    get_resp = client.get(f"/api/assets/{asset_id}", headers=headers)
    assert get_resp.status_code == 200
    assert get_resp.json()["name"] == "192.0.2.10"


def test_delete_asset(client):
    token = _get_token(client)
    headers = {"Authorization": f"Bearer {token}"}
    create_resp = client.post(
        "/api/assets", json={"name": "delete-me.example.com", "asset_type_id": 1}, headers=headers
    )
    asset_id = create_resp.json()["id"]

    delete_resp = client.delete(f"/api/assets/{asset_id}", headers=headers)
    assert delete_resp.status_code == 200

    get_resp = client.get(f"/api/assets/{asset_id}", headers=headers)
    assert get_resp.status_code == 404
