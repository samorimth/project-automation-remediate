import pytest
from fastapi.testclient import TestClient

from remediation.config import Settings
from remediation.main import create_app


@pytest.fixture
def settings(tmp_path) -> Settings:
    database_path = tmp_path / "lab.db"
    return Settings(
        app_version="0.1.0",
        environment="lab",
        database_url=f"sqlite:///{database_path}",
        lab_api_key="lab-test-key",
        log_level="INFO",
    )


@pytest.fixture
def app(settings):
    application = create_app(settings)
    yield application
    application.state.engine.dispose()


@pytest.fixture
def client(app):
    with TestClient(app) as test_client:
        yield test_client
