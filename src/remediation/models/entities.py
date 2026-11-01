"""Entidades locais do laboratório. A Fase 1 persiste o esquema sem orquestrar integrações."""

from datetime import UTC, datetime
from decimal import Decimal
from uuid import uuid4

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from remediation.models.base import Base
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
from remediation.models.types import enum_column


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id() -> str:
    return str(uuid4())


def created_at_column():
    return mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)


def optional_timestamp():
    return mapped_column(DateTime(timezone=True), nullable=True)


def indexed_fk(target: str, *, nullable: bool = False):
    return mapped_column(ForeignKey(target), nullable=nullable, index=True)


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    kind: Mapped[FindingKind] = mapped_column(enum_column(FindingKind), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[Severity] = mapped_column(enum_column(Severity), nullable=False)
    os_name: Mapped[str] = mapped_column(String(64), nullable=False)
    os_version: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    state: Mapped[FindingState] = mapped_column(
        enum_column(FindingState),
        nullable=False,
        default=FindingState.DETECTED,
    )
    remediation_criterion: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    detected_at: Mapped[datetime] = created_at_column()
    last_validated_at: Mapped[datetime | None] = optional_timestamp()
    instance_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    raw_payload: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    remediations: Mapped[list["Remediation"]] = relationship(back_populates="finding")
    validations: Mapped[list["ValidationRecord"]] = relationship(back_populates="finding")


class Experiment(Base):
    __tablename__ = "experiments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    case_code: Mapped[ExperimentCase] = mapped_column(enum_column(ExperimentCase), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    target_instance_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
    manual_elaboration_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    manual_review_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    human_intervention_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    estimated_cost_usd: Mapped[Decimal | None] = mapped_column(Numeric(12, 4), nullable=True)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = created_at_column()

    remediations: Mapped[list["Remediation"]] = relationship(back_populates="experiment")
    validations: Mapped[list["ValidationRecord"]] = relationship(back_populates="experiment")


class Remediation(Base):
    __tablename__ = "remediations"
    __table_args__ = (
        UniqueConstraint("finding_id", "attempt_number", name="uq_remediation_attempt"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    experiment_id: Mapped[str] = indexed_fk("experiments.id")
    finding_id: Mapped[str] = indexed_fk("findings.id")
    state: Mapped[RemediationState] = mapped_column(
        enum_column(RemediationState),
        nullable=False,
        default=RemediationState.GENERATED,
        index=True,
    )
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    diagnosis: Mapped[str | None] = mapped_column(Text, nullable=True)
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    script_content: Mapped[str | None] = mapped_column(Text, nullable=True)
    script_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    prerequisites: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    dangerous_commands: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    side_effects: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    verification_procedure: Mapped[str | None] = mapped_column(Text, nullable=True)
    rollback_guidance: Mapped[str | None] = mapped_column(Text, nullable=True)
    limitations: Mapped[str | None] = mapped_column(Text, nullable=True)
    static_analysis_result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    model_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    prompt_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    prompt_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    generation_started_at: Mapped[datetime | None] = optional_timestamp()
    generation_finished_at: Mapped[datetime | None] = optional_timestamp()
    generation_duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    review_started_at: Mapped[datetime | None] = optional_timestamp()
    review_finished_at: Mapped[datetime | None] = optional_timestamp()
    approved_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    approved_at: Mapped[datetime | None] = optional_timestamp()
    approved_script_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    gitlab_project_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    branch: Mapped[str | None] = mapped_column(String(255), nullable=True)
    commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    merge_request_iid: Mapped[str | None] = mapped_column(String(32), nullable=True)
    file_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    published_at: Mapped[datetime | None] = optional_timestamp()
    rejection_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = created_at_column()
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
    )

    experiment: Mapped[Experiment] = relationship(back_populates="remediations")
    finding: Mapped[Finding] = relationship(back_populates="remediations")
    approvals: Mapped[list["Approval"]] = relationship(back_populates="remediation")
    executions: Mapped[list["ExecutionRecord"]] = relationship(back_populates="remediation")
    validations: Mapped[list["ValidationRecord"]] = relationship(back_populates="remediation")


class Approval(Base):
    """Trilha imutável. A aprovação vigente exige o mesmo SHA-256 do script atual."""

    __tablename__ = "approvals"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    remediation_id: Mapped[str] = indexed_fk("remediations.id")
    script_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    approver: Mapped[str] = mapped_column(String(128), nullable=False)
    decision: Mapped[ApprovalDecision] = mapped_column(
        enum_column(ApprovalDecision),
        nullable=False,
    )
    comment: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = created_at_column()

    remediation: Mapped[Remediation] = relationship(back_populates="approvals")


class ExecutionRecord(Base):
    __tablename__ = "execution_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    remediation_id: Mapped[str] = indexed_fk("remediations.id")
    instance_id: Mapped[str] = mapped_column(String(64), nullable=False)
    ssm_command_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    script_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    started_at: Mapped[datetime | None] = optional_timestamp()
    finished_at: Mapped[datetime | None] = optional_timestamp()
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    stdout_redacted: Mapped[str] = mapped_column(Text, nullable=False, default="")
    stderr_redacted: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[ExecutionStatus] = mapped_column(
        enum_column(ExecutionStatus),
        nullable=False,
        default=ExecutionStatus.PENDING,
    )
    snapshot_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    remediation: Mapped[Remediation] = relationship(back_populates="executions")


class ValidationRecord(Base):
    __tablename__ = "validation_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    remediation_id: Mapped[str | None] = indexed_fk("remediations.id", nullable=True)
    experiment_id: Mapped[str] = indexed_fk("experiments.id")
    finding_id: Mapped[str] = indexed_fk("findings.id")
    phase: Mapped[ValidationPhase] = mapped_column(
        enum_column(ValidationPhase),
        nullable=False,
    )
    provider_validation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    evidence: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    passed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    checked_at: Mapped[datetime] = created_at_column()

    remediation: Mapped[Remediation | None] = relationship(back_populates="validations")
    experiment: Mapped[Experiment] = relationship(back_populates="validations")
    finding: Mapped[Finding] = relationship(back_populates="validations")


class LabInstance(Base):
    __tablename__ = "lab_instances"

    instance_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    account_id: Mapped[str] = mapped_column(String(32), nullable=False)
    region: Mapped[str] = mapped_column(String(32), nullable=False)
    expected_tags: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    ami_id: Mapped[str] = mapped_column(String(32), nullable=False)
    ubuntu_version: Mapped[str] = mapped_column(String(32), nullable=False)
    instance_type: Mapped[str] = mapped_column(String(32), nullable=False)
    authorized: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    environment: Mapped[str] = mapped_column(String(32), nullable=False, default="lab")
