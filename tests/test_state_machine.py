import pytest

from remediation.models.enums import RemediationState
from remediation.services.hashing import compute_sha256
from remediation.services.state_machine import (
    InvalidTransitionError,
    TransitionEvent,
    approval_is_current,
    effect_of_script_change,
    transition,
)

EXPECTED = {
    (RemediationState.GENERATED, TransitionEvent.MARK_REVIEWED): RemediationState.REVIEWED,
    (RemediationState.GENERATED, TransitionEvent.REJECT): RemediationState.REJECTED,
    (RemediationState.REVIEWED, TransitionEvent.APPROVE): RemediationState.APPROVED,
    (RemediationState.REVIEWED, TransitionEvent.REJECT): RemediationState.REJECTED,
    (RemediationState.REVIEWED, TransitionEvent.REQUEST_CHANGES): RemediationState.GENERATED,
    (RemediationState.APPROVED, TransitionEvent.REQUEST_CHANGES): RemediationState.GENERATED,
    (RemediationState.APPROVED, TransitionEvent.PUBLISH): RemediationState.PUBLISHED,
    (
        RemediationState.PUBLISHED,
        TransitionEvent.RECORD_EXECUTION_SUCCESS,
    ): RemediationState.EXECUTED,
    (
        RemediationState.PUBLISHED,
        TransitionEvent.RECORD_EXECUTION_FAILURE,
    ): RemediationState.FAILED,
    (
        RemediationState.EXECUTED,
        TransitionEvent.RECORD_VALIDATION_SUCCESS,
    ): RemediationState.VALIDATED,
    (
        RemediationState.EXECUTED,
        TransitionEvent.RECORD_VALIDATION_FAILURE,
    ): RemediationState.FAILED,
}

EVENTS = [
    TransitionEvent.MARK_REVIEWED,
    TransitionEvent.APPROVE,
    TransitionEvent.REJECT,
    TransitionEvent.REQUEST_CHANGES,
    TransitionEvent.PUBLISH,
    TransitionEvent.RECORD_EXECUTION_SUCCESS,
    TransitionEvent.RECORD_EXECUTION_FAILURE,
    TransitionEvent.RECORD_VALIDATION_SUCCESS,
    TransitionEvent.RECORD_VALIDATION_FAILURE,
]


def test_happy_path_reaches_validated_only_after_new_evidence():
    state = RemediationState.GENERATED
    for event in (
        TransitionEvent.MARK_REVIEWED,
        TransitionEvent.APPROVE,
        TransitionEvent.PUBLISH,
        TransitionEvent.RECORD_EXECUTION_SUCCESS,
    ):
        state = transition(state, event).state
        assert state is not RemediationState.VALIDATED

    validated = transition(state, TransitionEvent.RECORD_VALIDATION_SUCCESS)
    assert validated.state is RemediationState.VALIDATED
    assert validated.clear_approval is False


def test_every_state_and_event_is_explicit():
    for state in RemediationState:
        for event in EVENTS:
            expected = EXPECTED.get((state, event))
            if expected is None:
                with pytest.raises(InvalidTransitionError):
                    transition(state, event)
            else:
                assert transition(state, event).state is expected


def test_request_changes_clears_approval_before_publication():
    result = transition(RemediationState.APPROVED, TransitionEvent.REQUEST_CHANGES)

    assert result.state is RemediationState.GENERATED
    assert result.clear_approval is True
    assert result.clear_publication is False


def test_script_change_invalidates_approval_until_execution():
    original = compute_sha256("chmod 600 /var/lab/secret\n")
    changed = compute_sha256("chmod 644 /var/lab/secret\n")

    reviewed = effect_of_script_change(RemediationState.REVIEWED, original, changed)
    approved = effect_of_script_change(RemediationState.APPROVED, original, changed)
    published = effect_of_script_change(RemediationState.PUBLISHED, original, changed)
    generated = effect_of_script_change(RemediationState.GENERATED, original, changed)
    unchanged = effect_of_script_change(RemediationState.APPROVED, original, original)

    assert reviewed.state is RemediationState.GENERATED
    assert reviewed.clear_approval is True
    assert approved.state is RemediationState.GENERATED
    assert approved.clear_approval is True
    assert published.state is RemediationState.GENERATED
    assert published.clear_approval is True
    assert published.clear_publication is True
    assert generated.state is RemediationState.GENERATED
    assert generated.clear_approval is True
    assert generated.clear_publication is False
    assert unchanged.state is RemediationState.APPROVED
    assert unchanged.clear_approval is False


def test_script_change_after_execution_is_rejected():
    original = compute_sha256("echo antes\n")
    changed = compute_sha256("echo depois\n")

    for state in (
        RemediationState.EXECUTED,
        RemediationState.VALIDATED,
        RemediationState.REJECTED,
        RemediationState.FAILED,
    ):
        with pytest.raises(InvalidTransitionError) as caught:
            effect_of_script_change(state, original, changed)
        assert caught.value.event == "script_changed"


def test_approval_is_current_only_when_hash_and_state_match():
    script_hash = compute_sha256("systemctl reload ssh\n")

    assert approval_is_current(RemediationState.APPROVED, script_hash, script_hash) is True
    assert approval_is_current(RemediationState.PUBLISHED, script_hash, script_hash) is True
    assert approval_is_current(RemediationState.APPROVED, "0" * 64, script_hash) is False
    assert approval_is_current(RemediationState.APPROVED, None, script_hash) is False
    assert approval_is_current(RemediationState.REVIEWED, script_hash, script_hash) is False
    assert approval_is_current(RemediationState.GENERATED, script_hash, script_hash) is False
