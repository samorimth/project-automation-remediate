import src.aws_manager as aws_manager
import src.main as main
from src.aws_manager import (
    APPLY_COMMAND,
    DESTROY_COMMAND,
    AuthorizationError,
)
from src.config import APPLY_AUTHORIZATION_PHRASE, DESTROY_AUTHORIZATION_PHRASE


def _record_terraform(monkeypatch):
    calls = []

    def fake_run(args):
        calls.append(args)
        return 0

    monkeypatch.setattr(aws_manager, "run_terraform", fake_run)
    return calls


def test_apply_without_phrase_does_not_call_terraform(monkeypatch):
    calls = _record_terraform(monkeypatch)
    try:
        aws_manager.apply_infrastructure(authorize=None)
    except AuthorizationError:
        pass
    else:
        raise AssertionError("apply sem frase deveria ter sido recusado")
    assert calls == []


def test_apply_with_wrong_phrase_does_not_call_terraform(monkeypatch):
    calls = _record_terraform(monkeypatch)
    try:
        aws_manager.apply_infrastructure(authorize="sim")
    except AuthorizationError:
        pass
    else:
        raise AssertionError("frase incorreta deveria ter sido recusada")
    assert calls == []


def test_destroy_without_phrase_does_not_call_terraform(monkeypatch):
    calls = _record_terraform(monkeypatch)
    try:
        aws_manager.destroy_infrastructure(authorize=None)
    except AuthorizationError:
        pass
    else:
        raise AssertionError("destroy sem frase deveria ter sido recusado")
    assert calls == []


def test_provision_without_authorization_plans_and_does_not_apply(monkeypatch):
    calls = _record_terraform(monkeypatch)
    assert aws_manager.provision(authorize=None) == 0
    assert APPLY_COMMAND not in calls
    assert ["init", "-input=false"] in calls
    assert ["validate"] in calls
    assert ["plan", "-input=false"] in calls


def test_cleanup_without_authorization_does_not_destroy(monkeypatch):
    calls = _record_terraform(monkeypatch)
    assert aws_manager.cleanup(authorize=None) == 0
    assert DESTROY_COMMAND not in calls
    assert ["plan", "-destroy", "-input=false"] in calls


def test_authorized_apply_and_destroy_call_terraform(monkeypatch):
    calls = _record_terraform(monkeypatch)
    assert aws_manager.apply_infrastructure(authorize=APPLY_AUTHORIZATION_PHRASE) == 0
    assert aws_manager.destroy_infrastructure(authorize=DESTROY_AUTHORIZATION_PHRASE) == 0
    assert calls == [APPLY_COMMAND, DESTROY_COMMAND]


def test_deferred_commands_do_not_run_terraform(monkeypatch):
    calls = _record_terraform(monkeypatch)
    assert main.main(["generate", "--cve", "CVE-EXEMPLO"]) == 2
    assert main.main(["validate"]) == 2
    assert main.main(["execute", "--cve", "CVE-EXEMPLO"]) == 2
    assert main.main(["verify", "--cve", "CVE-EXEMPLO"]) == 2
    assert main.main(["report"]) == 2
    assert calls == []


def test_main_refuses_apply_when_phrase_is_wrong(monkeypatch):
    calls = _record_terraform(monkeypatch)
    code = main.main(["provision", "--authorize", "autorizo"])
    assert code == 1
    assert APPLY_COMMAND not in calls
