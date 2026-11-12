"""Orquestra uma repetição do experimento (generate → validate → [execute] → verify)."""

from __future__ import annotations

import json
from pathlib import Path

from .config import GENERATED_SCRIPTS_DIR, SCENARIOS_DIR, Settings, ConfigError
from .cve_validator import check_package_version, remediation_succeeded
from .metrics import ExperimentMetrics
from .openai_client import GenerationResult, generate_for_cve
from .prompt_builder import build_prompt, load_scenario
from .report_generator import append_experiment
from .script_validator import ValidationReport, validate_script
from .ssm_executor import (
    execute_script,
    require_execute_authorization,
    resolve_instance_id,
)


def latest_generation_dir(cve_id: str) -> Path:
    base = GENERATED_SCRIPTS_DIR / cve_id
    if not base.is_dir():
        raise ConfigError(f"Nenhuma geração encontrada para {cve_id}.")
    reps = sorted(base.glob("rep*"))
    if not reps:
        raise ConfigError(f"Nenhuma pasta rep* em {base}.")
    return reps[-1]


def run_generate(settings: Settings, cve_id: str) -> GenerationResult:
    scenario = load_scenario(cve_id)
    prompt = build_prompt(scenario)
    result = generate_for_cve(settings, cve_id, prompt)
    metrics = ExperimentMetrics(
        cve_id=cve_id,
        repetition=result.repetition,
        model=result.model,
        generation_latency_ms=result.latency_ms,
        prompt_tokens=result.prompt_tokens,
        completion_tokens=result.completion_tokens,
        total_tokens=result.total_tokens,
        validation_passed=None,
        execution_authorized=False,
        execution_status=None,
        version_before=None,
        version_after=None,
        remediation_success=None,
        notes="generate_only" if result.ok else f"generate_error:{result.error}",
    )
    append_experiment(metrics)
    return result


def run_validate(
    cve_id: str,
    *,
    generation_dir: Path | None = None,
) -> ValidationReport:
    scenario = load_scenario(cve_id)
    directory = generation_dir or latest_generation_dir(cve_id)
    script_path = directory / "remediation.sh"
    if not script_path.is_file():
        raise ConfigError(f"remediation.sh ausente em {directory}")
    report = validate_script(script_path, package_name=scenario.package_name)
    # Atualiza métrica pontual da repetição
    rep = int(directory.name.replace("rep", ""))
    append_experiment(
        ExperimentMetrics(
            cve_id=cve_id,
            repetition=rep,
            model=_read_model(directory),
            generation_latency_ms=None,
            prompt_tokens=None,
            completion_tokens=None,
            total_tokens=None,
            validation_passed=report.passed,
            execution_authorized=False,
            execution_status=None,
            version_before=None,
            version_after=None,
            remediation_success=None,
            notes="validate",
        )
    )
    return report


def run_execute(
    settings: Settings,
    cve_id: str,
    *,
    authorize: str | None,
    instance_id: str | None = None,
    generation_dir: Path | None = None,
) -> dict:
    # Autorização antes de qualquer chamada AWS ou leitura de script IA.
    require_execute_authorization(authorize)
    scenario = load_scenario(cve_id)
    directory = generation_dir or latest_generation_dir(cve_id)
    script_path = directory / "remediation.sh"
    resolved = resolve_instance_id(
        instance_id or scenario.instance_id_hint,
        SCENARIOS_DIR / cve_id / "evidence" / "before.json",
    )
    before = check_package_version(
        settings=settings,
        instance_id=resolved,
        scenario=scenario,
        phase="before_execute",
        output_dir=directory,
    )
    ssm_result = execute_script(
        settings=settings,
        instance_id=resolved,
        script_path=script_path,
        authorize=authorize,
    )
    after = check_package_version(
        settings=settings,
        instance_id=resolved,
        scenario=scenario,
        phase="after_execute",
        output_dir=directory,
    )
    success = remediation_succeeded(before, after)
    rep = int(directory.name.replace("rep", ""))
    append_experiment(
        ExperimentMetrics(
            cve_id=cve_id,
            repetition=rep,
            model=_read_model(directory),
            generation_latency_ms=None,
            prompt_tokens=None,
            completion_tokens=None,
            total_tokens=None,
            validation_passed=True,
            execution_authorized=True,
            execution_status=ssm_result.status,
            version_before=before.installed_version,
            version_after=after.installed_version,
            remediation_success=success,
            notes="execute",
        )
    )
    return {
        "ssm": ssm_result.to_dict(),
        "before": before.to_dict(),
        "after": after.to_dict(),
        "remediation_success": success,
    }


def run_verify(
    settings: Settings,
    cve_id: str,
    *,
    instance_id: str | None = None,
    generation_dir: Path | None = None,
) -> dict:
    scenario = load_scenario(cve_id)
    directory = generation_dir or (
        latest_generation_dir(cve_id)
        if (GENERATED_SCRIPTS_DIR / cve_id).is_dir()
        else SCENARIOS_DIR / cve_id / "evidence"
    )
    resolved = resolve_instance_id(
        instance_id or scenario.instance_id_hint,
        SCENARIOS_DIR / cve_id / "evidence" / "before.json",
    )
    check = check_package_version(
        settings=settings,
        instance_id=resolved,
        scenario=scenario,
        phase="independent",
        output_dir=Path(directory),
    )
    return check.to_dict()


def _read_model(directory: Path) -> str | None:
    meta = directory / "metadata.json"
    if not meta.is_file():
        return None
    data = json.loads(meta.read_text(encoding="utf-8"))
    return data.get("model")
