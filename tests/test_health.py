from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from remediation.api.deps import get_session
from remediation.schemas.health import HealthResponse


def test_health_is_public_and_reports_database(client):
    response = client.get("/health")

    assert response.status_code == 200
    body = HealthResponse.model_validate(response.json())
    assert body.status == "ok"
    assert body.version == "0.1.0"
    assert body.database == "ok"


def test_openapi_lists_only_health(client):
    response = client.get("/openapi.json")

    assert response.status_code == 200
    assert set(response.json()["paths"]) == {"/health"}


def test_health_reports_database_outage(app):
    class _BrokenSession:
        def execute(self, *_args, **_kwargs):
            raise OperationalError("SELECT 1", {}, Exception("down"))

    def override_session():
        yield _BrokenSession()

    app.dependency_overrides[get_session] = override_session
    response = TestClient(app).get("/health")

    assert response.status_code == 503
    assert response.json() == {
        "status": "degraded",
        "version": "0.1.0",
        "database": "error",
    }


def test_unknown_route_uses_error_envelope(client):
    response = client.get("/remediations")

    assert response.status_code == 404
    assert response.json() == {
        "error": {
            "code": "http_error",
            "message": "Not Found",
            "details": {},
        }
    }
