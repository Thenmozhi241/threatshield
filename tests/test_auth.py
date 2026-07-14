"""Tests for registration and login endpoints."""


def test_register_new_user(client):
    response = client.post(
        "/api/auth/register",
        json={
            "username": "testuser",
            "email": "testuser@example.com",
            "password": "TestPassword123",
            "full_name": "Test User",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert "access_token" in body
    assert body["token_type"] == "bearer"


def test_register_duplicate_username_fails(client):
    payload = {
        "username": "dupeuser",
        "email": "dupe1@example.com",
        "password": "TestPassword123",
    }
    first = client.post("/api/auth/register", json=payload)
    assert first.status_code == 200

    payload["email"] = "dupe2@example.com"
    second = client.post("/api/auth/register", json=payload)
    assert second.status_code == 400


def test_login_success(client):
    client.post(
        "/api/auth/register",
        json={"username": "loginuser", "email": "login@example.com", "password": "TestPassword123"},
    )
    response = client.post(
        "/api/auth/login",
        data={"username": "loginuser", "password": "TestPassword123"},
    )
    assert response.status_code == 200
    assert "access_token" in response.json()


def test_login_wrong_password_fails(client):
    client.post(
        "/api/auth/register",
        json={"username": "wrongpass", "email": "wrongpass@example.com", "password": "TestPassword123"},
    )
    response = client.post(
        "/api/auth/login",
        data={"username": "wrongpass", "password": "IncorrectPassword"},
    )
    assert response.status_code == 401
