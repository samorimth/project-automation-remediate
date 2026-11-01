from typing import Annotated

from fastapi import Depends
from fastapi.testclient import TestClient
from pydantic import BaseModel

from remediation.api.deps import api_key_is_valid, require_api_key
from remediation.api.errors import APIError


class _Payload(BaseModel):
    name: str


def test_api_key_rejects_missing_expected_and_mismatch():
    assert api_key_is_valid(None, "lab-test-key") is False
    assert api_key_is_valid("", "lab-test-key") is False
    assert api_key_is_valid("lab-test-key", "") is False
    assert api_key_is_valid("other", "lab-test-key") is False
    assert api_key_is_valid("lab-test-key", "lab-test-key") is True


def test_protected_dependency_and_validation_envelope(app):
    @app.post("/_probe")
    def probe(body: _Payload, _auth: Annotated[None, Depends(require_api_key)]) -> dict[str, str]:
        return {"name": body.name}

    client = TestClient(app)

    missing = client.post("/_probe", json={"name": "lab"})
    assert missing.status_code == 401
    assert missing.json()["error"]["code"] == "unauthorized"

    wrong = client.post("/_probe", headers={"X-API-Key": "wrong"}, json={"name": "lab"})
    assert wrong.status_code == 401

    invalid = client.post("/_probe", headers={"X-API-Key": "lab-test-key"}, json={})
    assert invalid.status_code == 422
    assert invalid.json()["error"]["code"] == "validation_error"

    accepted = client.post(
        "/_probe",
        headers={"X-API-Key": "lab-test-key"},
        json={"name": "lab"},
    )
    assert accepted.status_code == 200
    assert accepted.json() == {"name": "lab"}


def test_api_error_shape(app):
    @app.get("/_conflict")
    def conflict():
        raise APIError(
            status_code=409,
            code="invalid_transition",
            message="Transição inválida.",
            details={"from": "GENERATED", "event": "approve"},
        )

    response = TestClient(app).get("/_conflict")

    assert response.status_code == 409
    assert response.json() == {
        "error": {
            "code": "invalid_transition",
            "message": "Transição inválida.",
            "details": {"from": "GENERATED", "event": "approve"},
        }
    }
