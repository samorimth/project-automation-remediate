import pytest

import src.experiment_runner as experiment_runner
from src.aws_manager import AuthorizationError
from src.config import EXECUTE_AUTHORIZATION_PHRASE, load_settings
from src.experiment_runner import run_execute
from src.ssm_executor import require_execute_authorization


def test_execute_requires_exact_phrase():
    with pytest.raises(AuthorizationError):
        require_execute_authorization(None)
    with pytest.raises(AuthorizationError):
        require_execute_authorization("autorizo")
    require_execute_authorization(EXECUTE_AUTHORIZATION_PHRASE)


def test_execute_does_not_call_ssm_without_validated_script(monkeypatch, tmp_path):
    called = []

    def fail_check(**kwargs):
        called.append("check")
        raise AssertionError("SSM não deveria ser chamado")

    def fail_exec(**kwargs):
        called.append("exec")
        raise AssertionError("SSM não deveria ser chamado")

    generation = tmp_path / "rep01"
    generation.mkdir()
    monkeypatch.setattr(experiment_runner, "check_package_version", fail_check)
    monkeypatch.setattr(experiment_runner, "execute_script", fail_exec)
    monkeypatch.setattr(
        experiment_runner, "latest_generation_dir", lambda cve_id: generation
    )

    with pytest.raises(AuthorizationError, match="Nenhum comando foi enviado ao SSM"):
        run_execute(
            load_settings(),
            "CVE-2024-38428",
            authorize=EXECUTE_AUTHORIZATION_PHRASE,
        )
    assert called == []
