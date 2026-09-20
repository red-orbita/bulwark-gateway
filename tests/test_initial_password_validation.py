"""Initial password change rejects malformed data before user-store access."""

from unittest.mock import Mock

import httpx
import pytest
from fastapi import FastAPI


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """No real user store for validation tests."""


@pytest.mark.parametrize("field,value", [
    ("username", []), ("username", "a" * 129), ("username", ""),
    ("current_password", {}), ("current_password", "a" * 1025),
    ("new_password", 42), ("new_password", "short"),
    ("new_password", "a" * 73), ("new_password", "\u00e9" * 37),
    ("extra", "ignored-before"),
])
async def test_invalid_initial_password_request_never_reaches_store(monkeypatch, field, value):
    from admin.routes import auth

    store = Mock(side_effect=AssertionError("Store must not be reached"))
    monkeypatch.setattr(auth, "get_user_store", store)
    app = FastAPI()
    app.include_router(auth.router)
    body = {"username": "operator", "current_password": "ExistingPassword1!", "new_password": "ChangedPassword2!"}
    body[field] = value
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/force-change-password", json=body)
    assert response.status_code == 422
    store.assert_not_called()


@pytest.mark.parametrize("password", ["ChangedPassword2!", "A1!" + "\u00e9" * 34])
def test_valid_ascii_and_unicode_passwords_supported(password):
    from admin.models.auth import InitialPasswordChangeRequest

    value = InitialPasswordChangeRequest(username="operator", current_password="existing", new_password=password)
    assert value.new_password == password


async def test_actual_admin_validation_never_echoes_password():
    from admin.main import app

    secret = "PRIVATE-PASSWORD-DO-NOT-ECHO" * 5
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/admin/auth/force-change-password", json={
            "username": "operator", "current_password": "current", "new_password": secret})
    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid request data"}
    assert secret not in response.text
