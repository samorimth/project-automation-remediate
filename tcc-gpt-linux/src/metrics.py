"""Coleta de métricas reais de uma execução experimental (sem preenchimento fictício)."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class ExperimentMetrics:
    cve_id: str
    repetition: int
    model: str | None
    generation_latency_ms: int | None
    prompt_tokens: int | None
    completion_tokens: int | None
    total_tokens: int | None
    validation_passed: bool | None
    execution_authorized: bool
    execution_status: str | None
    version_before: str | None
    version_after: str | None
    remediation_success: bool | None
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_csv_row(self) -> dict[str, Any]:
        return self.to_dict()
