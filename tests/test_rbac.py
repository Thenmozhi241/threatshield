"""Tests for RBAC: a default 'viewer' user must not access admin-only routes."""


def _get_token(client, username="rbacuser"):
    client.post(
        "/api/auth/register",
        json={"username": username, "email": f"{username}@example.com", "password": "TestPassword123"},
    )
    response = client.post("/api/auth/login", data={"username": username, "password": "TestPassword123"})
    return response.json()["access_token"]


def test_viewer_cannot_list_users(client):
    token = _get_token(client)
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/api/users", headers=headers)
    assert response.status_code == 403


def test_viewer_cannot_create_user(client):
    token = _get_token(client)
    headers = {"Authorization": f"Bearer {token}"}
    response = client.post(
        "/api/users",
        json={
            "username": "newone",
            "email": "newone@example.com",
            "password": "TestPassword123",
            "role_id": 1,
        },
        headers=headers,
    )
    assert response.status_code == 403


def test_unauthenticated_request_rejected(client):
    response = client.get("/api/users")
    assert response.status_code == 401
