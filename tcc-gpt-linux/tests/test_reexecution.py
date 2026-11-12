import pytest

from src.aws_manager import AuthorizationError
from src.config import LAB_ROOT
from src.fresh_instance import MethodologyError, reject_restore_baseline
from src.reexecution import assert_evidence_dir, classify_reexecution


def test_success_requires_version_and_functional_wget():
    kind, _reason = classify_reexecution(
        validation_passed=True,
        initial_vulnerable=True,
        executed=True,
        version_after="1.21.4-1ubuntu4.5",
        functional_ok=True,
        fresh_instance=True,
    )
    assert kind == "SUCESSO"


def test_wrong_initial_state_does_not_run():
    kind, reason = classify_reexecution(
        validation_passed=True,
        initial_vulnerable=False,
        executed=False,
        version_after=None,
        functional_ok=None,
        fresh_instance=True,
    )
    assert kind == "INCONCLUSIVO"
    assert "não foi executado" in reason


def test_reexecution_cannot_write_over_original_scripts():
    with pytest.raises(AuthorizationError):
        assert_evidence_dir(
            LAB_ROOT / "generated_scripts" / "CVE-2024-38428" / "rep02" / "ssm-execute.json"
        )


def test_prepare_apply_is_not_a_repetition_baseline():
    with pytest.raises(MethodologyError):
        reject_restore_baseline("prepare.sh --apply")
