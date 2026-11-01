from remediation.config import get_settings


def test_settings_read_environment(monkeypatch, tmp_path):
    database_path = tmp_path / "from-env.db"
    monkeypatch.setenv("LAB_API_KEY", "from-env")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{database_path}")
    monkeypatch.setenv("APP_VERSION", "0.1.0")
    get_settings.cache_clear()

    settings = get_settings()

    assert settings.lab_api_key == "from-env"
    assert settings.database_url == f"sqlite:///{database_path}"
    get_settings.cache_clear()
