"""Transições explícitas da remediação.

DETECTED pertence ao finding e não aparece aqui. Código de saída zero não
valida a correção: só RECORD_VALIDATION_SUCCESS, a partir de EXECUTED, chega
a VALIDATED. Mudar o script invalida a aprovação e devolve o fluxo a GENERATED
enquanto a execução ainda não aconteceu.
"""

from dataclasses import dataclass

from remediation.models.enums import RemediationState


class TransitionEvent:
    MARK_REVIEWED = "mark_reviewed"
    APPROVE = "approve"
    REJECT = "reject"
    REQUEST_CHANGES = "request_changes"
    PUBLISH = "publish"
    RECORD_EXECUTION_SUCCESS = "record_execution_success"
    RECORD_EXECUTION_FAILURE = "record_execution_failure"
    RECORD_VALIDATION_SUCCESS = "record_validation_success"
    RECORD_VALIDATION_FAILURE = "record_validation_failure"


class InvalidTransitionError(Exception):
    def __init__(self, state: RemediationState, event: str) -> None:
        self.state = state
        self.event = event
        super().__init__(f"Transição inválida: {state.value} não aceita {event}.")


@dataclass(frozen=True)
class TransitionResult:
    state: RemediationState
    clear_approval: bool
    clear_publication: bool


@dataclass(frozen=True)
class ScriptChangeEffect:
    state: RemediationState
    clear_approval: bool
    clear_publication: bool


_TRANSITIONS: dict[tuple[RemediationState, str], TransitionResult] = {
    (RemediationState.GENERATED, TransitionEvent.MARK_REVIEWED): TransitionResult(
        RemediationState.REVIEWED,
        clear_approval=False,
        clear_publication=False,
    ),
    (RemediationState.GENERATED, TransitionEvent.REJECT): TransitionResult(
        RemediationState.REJECTED,
        clear_approval=False,
        clear_publication=False,
    ),
    (RemediationState.REVIEWED, TransitionEvent.APPROVE): TransitionResult(
        RemediationState.APPROVED,
        clear_approval=False,
        clear_publication=False,
    ),
    (RemediationState.REVIEWED, TransitionEvent.REJECT): TransitionResult(
        RemediationState.REJECTED,
        clear_approval=False,
        clear_publication=False,
    ),
    (RemediationState.REVIEWED, TransitionEvent.REQUEST_CHANGES): TransitionResult(
        RemediationState.GENERATED,
        clear_approval=True,
        clear_publication=False,
    ),
    (RemediationState.APPROVED, TransitionEvent.REQUEST_CHANGES): TransitionResult(
        RemediationState.GENERATED,
        clear_approval=True,
        clear_publication=False,
    ),
    (RemediationState.APPROVED, TransitionEvent.PUBLISH): TransitionResult(
        RemediationState.PUBLISHED,
        clear_approval=False,
        clear_publication=False,
    ),
    (RemediationState.PUBLISHED, TransitionEvent.RECORD_EXECUTION_SUCCESS): TransitionResult(
        RemediationState.EXECUTED,
        clear_approval=False,
        clear_publication=False,
    ),
    (RemediationState.PUBLISHED, TransitionEvent.RECORD_EXECUTION_FAILURE): TransitionResult(
        RemediationState.FAILED,
        clear_approval=False,
        clear_publication=False,
    ),
    (RemediationState.EXECUTED, TransitionEvent.RECORD_VALIDATION_SUCCESS): TransitionResult(
        RemediationState.VALIDATED,
        clear_approval=False,
        clear_publication=False,
    ),
    (RemediationState.EXECUTED, TransitionEvent.RECORD_VALIDATION_FAILURE): TransitionResult(
        RemediationState.FAILED,
        clear_approval=False,
        clear_publication=False,
    ),
}

_REWIND_ON_SCRIPT_CHANGE = {
    RemediationState.REVIEWED,
    RemediationState.APPROVED,
    RemediationState.PUBLISHED,
}

_APPROVAL_STATES = {
    RemediationState.APPROVED,
    RemediationState.PUBLISHED,
    RemediationState.EXECUTED,
    RemediationState.VALIDATED,
}


def transition(state: RemediationState, event: str) -> TransitionResult:
    try:
        return _TRANSITIONS[(state, event)]
    except KeyError as exc:
        raise InvalidTransitionError(state, event) from exc


def effect_of_script_change(
    state: RemediationState,
    previous_sha256: str | None,
    new_sha256: str,
) -> ScriptChangeEffect:
    if previous_sha256 == new_sha256:
        return ScriptChangeEffect(state, clear_approval=False, clear_publication=False)
    if state is RemediationState.GENERATED:
        return ScriptChangeEffect(state, clear_approval=True, clear_publication=False)
    if state in _REWIND_ON_SCRIPT_CHANGE:
        return ScriptChangeEffect(
            RemediationState.GENERATED,
            clear_approval=True,
            clear_publication=state is RemediationState.PUBLISHED,
        )
    raise InvalidTransitionError(state, "script_changed")


def approval_is_current(
    state: RemediationState,
    approved_script_sha256: str | None,
    script_sha256: str,
) -> bool:
    if state not in _APPROVAL_STATES:
        return False
    return bool(approved_script_sha256) and approved_script_sha256 == script_sha256
