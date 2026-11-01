"""Enumeração compartilhada entre persistência e regras de transição."""

from enum import StrEnum


class FindingKind(StrEnum):
    CVE = "cve"
    INSECURE_CONFIG = "insecure_config"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingState(StrEnum):
    DETECTED = "DETECTED"
    REMEDIATED = "REMEDIATED"


class ExperimentCase(StrEnum):
    SSH_CONFIG = "ssh_config"
    FILE_PERMISSIONS = "file_permissions"
    PACKAGE_OR_CONFIG = "package_or_config"


class RemediationState(StrEnum):
    GENERATED = "GENERATED"
    REVIEWED = "REVIEWED"
    APPROVED = "APPROVED"
    PUBLISHED = "PUBLISHED"
    EXECUTED = "EXECUTED"
    VALIDATED = "VALIDATED"
    REJECTED = "REJECTED"
    FAILED = "FAILED"


class ApprovalDecision(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"


class ExecutionStatus(StrEnum):
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


class ValidationPhase(StrEnum):
    BEFORE = "before"
    AFTER = "after"
