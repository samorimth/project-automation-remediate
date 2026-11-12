from src.aws_manager import AuthorizationError
from src.less_experiment import classify_less, run
import pytest


def test_success_needs_the_fixed_version_and_a_local_read():
    kind, reason = classify_less(
        validation_passed=True,
        initial_vulnerable=True,
        functional_before_ok=True,
        executed=True,
        version_after="590-2ubuntu2.1",
        functional_ok=True,
        fresh_instance=True,
    )
    assert kind == "SUCESSO"
    assert "590-2ubuntu2.1" in reason


def test_a_rejected_script_is_not_sent():
    kind, reason = classify_less(
        validation_passed=False,
        initial_vulnerable=True,
        functional_before_ok=True,
        executed=False,
        version_after=None,
        functional_ok=None,
        fresh_instance=True,
    )
    assert kind == "BLOQUEADO"
    assert "enviado" in reason


def test_a_failed_functional_probe_blocks_execution():
    kind, _reason = classify_less(
        validation_passed=True,
        initial_vulnerable=True,
        functional_before_ok=False,
        executed=False,
        version_after=None,
        functional_ok=None,
        fresh_instance=True,
    )
    assert kind == "INCONCLUSIVO"


def test_run_refuses_without_the_three_phrases():
    with pytest.raises(AuthorizationError):
        run("nao", "nao", "nao")
