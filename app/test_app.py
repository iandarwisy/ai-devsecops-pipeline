import pytest
from app.app import create_app


@pytest.fixture
def client(tmp_path):
    db_file = str(tmp_path / "test_portal.db")
    app = create_app(db_path=db_file)
    app.config["TESTING"] = True
    with app.test_client() as test_client:
        yield test_client


def test_health_endpoint(client):
    res = client.get("/health")
    assert res.status_code == 200
    assert res.get_json()["status"] == "healthy"


def test_login_success(client):
    res = client.post("/login", json={"username": "ian", "password": "DevPass#2026"})
    assert res.status_code == 200
    assert res.get_json()["user"]["role"] == "developer"


def test_login_invalid_password(client):
    res = client.post("/login", json={"username": "ian", "password": "wrongpassword"})
    assert res.status_code == 401


def test_search_users(client):
    res = client.get("/users?username=admin")
    assert res.status_code == 200
    data = res.get_json()
    assert len(data) == 1
    assert data[0]["username"] == "admin"
    assert "password_hash" not in data[0]