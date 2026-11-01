from datetime import UTC, datetime
from decimal import Decimal

import pytest
from sqlalchemy import inspect, select
from sqlalchemy.exc import IntegrityError

from remediation.db import ping_database
from remediation.models import (
    Approval,
    ExecutionRecord,
    Experiment,
    Finding,
    LabInstance,
    Remediation,
    ValidationRecord,
)
from remediation.models.enums import (
    ApprovalDecision,
    ExecutionStatus,
    ExperimentCase,
    FindingKind,
    FindingState,
    RemediationState,
    Severity,
    ValidationPhase,
)
from remediation.services.hashing import compute_sha256

EXPECTED_TABLES = {
    "findings",
    "experiments",
    "remediations",
    "approvals",
    "execution_records",
    "validation_records",
    "lab_instances",
}


def test_schema_contains_laboratory_tables(app):
    names = set(inspect(app.state.engine).get_table_names())

    assert EXPECTED_TABLES <= names


def test_roundtrip_persists_finding_remediation_and_evidence(app):
    session = app.state.session_factory()
    script = "#!/bin/bash\nchmod 600 /var/lab/secret\n"
    script_hash = compute_sha256(script)
    now = datetime.now(UTC)
    try:
        finding = Finding(
            id="lab-file-permissions",
            kind=FindingKind.INSECURE_CONFIG,
            description="Arquivo de laboratório com permissão excessiva.",
            severity=Severity.HIGH,
            os_name="ubuntu",
            os_version="24.04",
            evidence={"path": "/var/lab/secret", "mode": "0666"},
            state=FindingState.DETECTED,
            remediation_criterion="O modo do arquivo deve ser 0600.",
            source="mock",
            detected_at=now,
            instance_id="i-lab",
            raw_payload={"untrusted": "scanner text"},
        )
        experiment = Experiment(
            name="Caso 2",
            case_code=ExperimentCase.FILE_PERMISSIONS,
            description="Permissões de arquivo.",
            target_instance_id="i-lab",
            manual_elaboration_seconds=900,
            manual_review_seconds=300,
            human_intervention_count=1,
            estimated_cost_usd=Decimal("0.2500"),
            notes="Tempo manual lançado pelo pesquisador.",
        )
        session.add_all([finding, experiment])
        session.flush()
        remediation = Remediation(
            experiment_id=experiment.id,
            finding_id=finding.id,
            state=RemediationState.GENERATED,
            attempt_number=1,
            script_content=script,
            script_sha256=script_hash,
            prerequisites=["acesso de laboratório"],
            dangerous_commands=[],
            side_effects=["o arquivo deixa de ser legível por outros usuários"],
        )
        session.add(remediation)
        session.flush()
        session.add_all(
            [
                Approval(
                    remediation_id=remediation.id,
                    script_sha256=script_hash,
                    approver="pesquisador",
                    decision=ApprovalDecision.APPROVED,
                    comment="Revisão humana registrada.",
                ),
                ExecutionRecord(
                    remediation_id=remediation.id,
                    instance_id="i-lab",
                    script_sha256=script_hash,
                    status=ExecutionStatus.PENDING,
                ),
                ValidationRecord(
                    remediation_id=remediation.id,
                    experiment_id=experiment.id,
                    finding_id=finding.id,
                    phase=ValidationPhase.BEFORE,
                    provider_validation_id="validation-before-1",
                    evidence={"mode": "0666"},
                    passed=False,
                ),
                LabInstance(
                    instance_id="i-lab",
                    account_id="123456789012",
                    region="us-east-1",
                    expected_tags={"Environment": "lab", "Project": "tcc-remediation"},
                    ami_id="ami-example",
                    ubuntu_version="24.04",
                    instance_type="t3.micro",
                    authorized=True,
                    environment="lab",
                ),
            ]
        )
        session.commit()

        stored = session.get(Remediation, remediation.id)
        approval = session.scalars(select(Approval)).one()
        validation = session.scalars(select(ValidationRecord)).one()
        instance = session.get(LabInstance, "i-lab")
        assert stored is not None
        assert stored.finding.state is FindingState.DETECTED
        assert stored.experiment.case_code is ExperimentCase.FILE_PERMISSIONS
        assert stored.experiment.estimated_cost_usd == Decimal("0.2500")
        assert stored.script_sha256 == script_hash
        assert approval.approver == "pesquisador"
        assert approval.script_sha256 == script_hash
        assert validation.phase is ValidationPhase.BEFORE
        assert validation.passed is False
        assert instance is not None
        assert instance.authorized is True
        ping_database(session)
    finally:
        session.close()


def test_foreign_key_rejects_unknown_finding(app):
    session = app.state.session_factory()
    try:
        experiment = Experiment(name="Caso 1", case_code=ExperimentCase.SSH_CONFIG)
        session.add(experiment)
        session.flush()
        session.add(
            Remediation(
                experiment_id=experiment.id,
                finding_id="ausente",
                attempt_number=1,
            )
        )
        with pytest.raises(IntegrityError):
            session.commit()
    finally:
        session.rollback()
        session.close()


def test_attempt_number_is_unique_per_finding(app):
    session = app.state.session_factory()
    try:
        finding = Finding(
            id="lab-ssh",
            kind=FindingKind.INSECURE_CONFIG,
            description="SSH de laboratório.",
            severity=Severity.MEDIUM,
            os_name="ubuntu",
            os_version="24.04",
            remediation_criterion="PermitRootLogin deve ser no.",
            source="mock",
            detected_at=datetime.now(UTC),
        )
        experiment = Experiment(name="Caso 1", case_code=ExperimentCase.SSH_CONFIG)
        session.add_all([finding, experiment])
        session.flush()
        session.add(
            Remediation(experiment_id=experiment.id, finding_id=finding.id, attempt_number=1)
        )
        session.add(
            Remediation(experiment_id=experiment.id, finding_id=finding.id, attempt_number=1)
        )
        with pytest.raises(IntegrityError):
            session.commit()
    finally:
        session.rollback()
        session.close()
