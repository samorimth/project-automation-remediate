"""Separação dos registros históricos em três categorias.

Lê somente arquivos já gravados. Campos sem evidência ficam vazios.
Não reescreve experiments.json nem os scripts gerados.
"""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
from typing import Any

INFRASTRUCTURE_FIELDS = [
    "attempt_id",
    "attempt_number",
    "timestamp_utc",
    "aws_region",
    "result",
    "failure_reason",
    "resources_created",
    "cleanup_status",
    "source",
    "notes",
]

API_FIELDS = [
    "call_id",
    "timestamp_utc",
    "repetition",
    "model_recorded",
    "model_requested_separately",
    "model_returned_separately",
    "response_id",
    "http_status",
    "latency_ms",
    "prompt_tokens",
    "completion_tokens",
    "total_tokens",
    "reasoning_tokens",
    "reasoning_effort",
    "script_generated",
    "failure_reason",
    "source",
]

RUN_FIELDS = [
    "experiment_id",
    "api_call_id",
    "infrastructure_attempt_id",
    "cve_id",
    "repetition",
    "script_path",
    "script_sha256",
    "ami_id",
    "instance_id",
    "initial_state",
    "validation_recorded",
    "execution_status",
    "version_before",
    "version_after",
    "recorded_remediation_success",
    "classification",
    "classification_reason",
    "source",
]

# Tabela pública já citada em docs/limitacoes.md. Não é fatura.
PUBLISHED_INPUT_USD_PER_MILLION = 0.10
PUBLISHED_OUTPUT_USD_PER_MILLION = 0.50


def estimate_generation_cost_usd(
    prompt_tokens: int | None,
    completion_tokens: int | None,
) -> str:
    """Custo estimado pela tabela pública. Vazio quando a API não devolveu tokens."""
    if prompt_tokens is None or completion_tokens is None:
        return ""
    amount = (
        prompt_tokens * PUBLISHED_INPUT_USD_PER_MILLION
        + completion_tokens * PUBLISHED_OUTPUT_USD_PER_MILLION
    ) / 1_000_000
    return f"{amount:.6f}"


def infrastructure_attempts(root: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    status = root / "scenarios" / "CVE-2024-38428" / "evidence" / "STATUS.md"
    narrative = status.read_text(encoding="utf-8") if status.is_file() else ""
    if "Tentativas 1–2: secrets ausentes" in narrative:
        source = "scenarios/CVE-2024-38428/evidence/STATUS.md"
        rows.extend(
            [
                _infra(
                    "INF-01",
                    "1",
                    "",
                    "",
                    "falha",
                    "segredos ausentes",
                    "",
                    "",
                    source,
                    "Somente a narrativa do STATUS.md. Não há JSON próprio nem horário.",
                ),
                _infra(
                    "INF-02",
                    "2",
                    "",
                    "",
                    "falha",
                    "segredos ausentes",
                    "",
                    "",
                    source,
                    "Somente a narrativa do STATUS.md. Não há JSON próprio nem horário.",
                ),
                _infra(
                    "INF-03",
                    "3",
                    "",
                    "",
                    "falha",
                    "SCP negou EC2",
                    "0",
                    "não se aplica",
                    source,
                    "A narrativa agrupa as tentativas 3 e 4. Região e horário não estão em JSON.",
                ),
            ]
        )
    blocked = _read(root / "results" / "CVE-2024-38428" / "execucao_bloqueada.json")
    if isinstance(blocked, dict):
        rows.append(
            _infra(
                "INF-04",
                str(blocked.get("attempt") or "4"),
                str(blocked.get("timestamp_utc") or ""),
                "",
                "falha",
                str(blocked.get("reason") or "SCP"),
                "0",
                "não se aplica",
                "results/CVE-2024-38428/execucao_bloqueada.json",
                "apply não executado; sonda EC2 negada. A região no JSON é o placeholder da variável de ambiente.",
            )
        )
    before = _read(root / "scenarios" / "CVE-2024-38428" / "evidence" / "before.json")
    cleanup = _read(root / "scenarios" / "CVE-2024-38428" / "evidence" / "cleanup-fase3.json")
    cleanup_status = ""
    if isinstance(cleanup, list) and cleanup:
        ok = sum(1 for item in cleanup if item.get("ok") is True)
        cleanup_status = f"{ok}/{len(cleanup)} itens com ok=true"
    if isinstance(before, dict):
        created = before.get("resources_added")
        rows.append(
            _infra(
                "INF-05",
                str(before.get("attempt") or "5"),
                str(before.get("timestamp_utc") or ""),
                str(before.get("aws_region") or ""),
                "sucesso" if before.get("terraform_apply_succeeded") else "falha",
                "",
                "" if created is None else str(created),
                cleanup_status,
                "scenarios/CVE-2024-38428/evidence/before.json",
                (
                    f"instance_id={before.get('instance_id') or ''}; "
                    f"ami_id={before.get('ami_id') or ''}; "
                    "AMI pública da Canonical, não uma AMI privada de referência."
                ),
            )
        )
    return rows


def api_calls(root: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    blocked = _read(
        root / "scenarios" / "CVE-2024-38428" / "evidence" / "fase3_generate_blocked.json"
    )
    if isinstance(blocked, dict):
        rows.append(
            {
                "call_id": "API-00",
                "timestamp_utc": str(blocked.get("timestamp_utc") or ""),
                "repetition": "",
                "model_recorded": "",
                "model_requested_separately": "",
                "model_returned_separately": "",
                "response_id": "",
                "http_status": "",
                "latency_ms": "",
                "prompt_tokens": "",
                "completion_tokens": "",
                "total_tokens": "",
                "reasoning_tokens": "",
                "reasoning_effort": "",
                "script_generated": "0",
                "failure_reason": str(blocked.get("classification") or "chave ausente"),
                "source": "scenarios/CVE-2024-38428/evidence/fase3_generate_blocked.json",
            }
        )
    ledger = _ledger(root)
    sequence = 0
    for event in ledger:
        notes = str(event.get("notes") or "")
        if not (notes.startswith("generate_error") or notes.startswith("generate_only")):
            continue
        sequence += 1
        repetition = event.get("repetition")
        meta = _metadata(root, repetition)
        failed = notes.startswith("generate_error")
        http = "429" if "429" in notes else ""
        rows.append(
            {
                "call_id": f"API-{sequence:02d}",
                "timestamp_utc": str((meta or {}).get("timestamp_utc") or ""),
                "repetition": _cell(repetition),
                "model_recorded": _cell((meta or event).get("model")),
                "model_requested_separately": "",
                "model_returned_separately": "",
                "response_id": "",
                "http_status": http if not failed or "429" in notes else "",
                "latency_ms": _cell(event.get("generation_latency_ms")),
                "prompt_tokens": _cell(event.get("prompt_tokens")),
                "completion_tokens": _cell(event.get("completion_tokens")),
                "total_tokens": _cell(event.get("total_tokens")),
                "reasoning_tokens": _cell((meta or {}).get("reasoning_tokens")),
                "reasoning_effort": _cell((meta or {}).get("reasoning_effort")),
                "script_generated": "0" if failed else "1",
                "failure_reason": notes if failed else "",
                "source": "results/experiments.json",
            }
        )
    return rows


def experimental_runs(root: Path) -> list[dict[str, str]]:
    calls = {row["repetition"]: row["call_id"] for row in api_calls(root) if row["repetition"]}
    before = _read(root / "scenarios" / "CVE-2024-38428" / "evidence" / "before.json")
    ami = ""
    instance = ""
    if isinstance(before, dict):
        ami = str(before.get("ami_id") or "")
        instance = str(before.get("instance_id") or "")
    rows: list[dict[str, str]] = []
    seen: set[int] = set()
    for event in _ledger(root):
        if not str(event.get("notes") or "").startswith("generate_"):
            continue
        repetition = int(event["repetition"])
        if repetition in seen:
            continue
        seen.add(repetition)
        rows.append(_run_row(root, repetition, calls.get(str(repetition), ""), ami, instance))
    return rows


def classify_run(
    *,
    script_exists: bool,
    validation_events: list[bool | None],
    execution_status: str,
    version_before: str,
    version_after: str,
    fixed_version: str,
    functional_test_recorded: bool,
    fresh_instance: bool,
) -> tuple[str, str]:
    """Classificação do protocolo atual. Não altera o booleano histórico."""
    if not script_exists:
        return "NAO_EXECUTADO", "A chamada não produziu remediation.sh."
    if validation_events and all(item is False for item in validation_events):
        return "BLOQUEADO", "Nenhuma validação registrada aprovou o script."
    if execution_status != "Success" or not version_before or not version_after:
        return "INCONCLUSIVO", "Não há execução SSM com versão antes e depois."
    if not functional_test_recorded or not fresh_instance:
        reasons = []
        if not fresh_instance:
            reasons.append("a mesma EC2 recebeu mais de uma repetição, com prepare.sh --apply entre elas")
        if not functional_test_recorded:
            reasons.append("não há teste funcional do wget nem saída de scanner")
        return (
            "INCONCLUSIVO",
            "A versão observada satisfaz o mínimo oficial, mas "
            + "; ".join(reasons)
            + f". Mínimo de referência: {fixed_version}.",
        )
    return (
        "SUCESSO",
        "Estado vulnerável, correção e teste funcional registrados em instância nova.",
    )


def _run_row(
    root: Path,
    repetition: int,
    call_id: str,
    ami: str,
    shared_instance: str,
) -> dict[str, str]:
    cve = "CVE-2024-38428"
    directory = root / "generated_scripts" / cve / f"rep{repetition:02d}"
    script = directory / "remediation.sh"
    script_exists = script.is_file() and script.stat().st_size > 0
    digest = hashlib.sha256(script.read_bytes()).hexdigest() if script_exists else ""
    events = [
        event.get("validation_passed")
        for event in _ledger(root)
        if event.get("repetition") == repetition and event.get("notes") == "validate"
    ]
    execute = [
        event
        for event in _ledger(root)
        if event.get("repetition") == repetition and event.get("notes") == "execute"
    ]
    execution = execute[-1] if execute else {}
    before = _read(directory / "verify_before_execute.json") or {}
    after = _read(directory / "verify_after_execute.json") or {}
    version_before = str(before.get("installed_version") or execution.get("version_before") or "")
    version_after = str(after.get("installed_version") or execution.get("version_after") or "")
    status = str(execution.get("execution_status") or "")
    recorded = execution.get("remediation_success")
    classification, reason = classify_run(
        script_exists=script_exists,
        validation_events=events,
        execution_status=status,
        version_before=version_before,
        version_after=version_after,
        fixed_version="1.21.4-1ubuntu4.1",
        functional_test_recorded=False,
        fresh_instance=False,
    )
    if classification == "INCONCLUSIVO" and repetition == 2:
        reason = (
            "A versão observada satisfaz o mínimo oficial, mas a instância "
            f"{shared_instance} também executou as repetições 3 e 4. "
            "Não há teste funcional do wget nem saída de scanner. "
            "Mínimo de referência: 1.21.4-1ubuntu4.1."
        )
    elif classification == "INCONCLUSIVO" and repetition in {3, 4}:
        reason = (
            "A versão observada satisfaz o mínimo oficial, mas o estado inicial "
            "foi restaurado com prepare.sh --apply na mesma EC2. "
            "Não há teste funcional do wget nem saída de scanner. "
            "Mínimo de referência: 1.21.4-1ubuntu4.1."
        )
    validation_text = ""
    if events:
        validation_text = ",".join("aprovada" if item else "reprovada" for item in events)
    return {
        "experiment_id": f"EXP-{cve}-rep{repetition:02d}",
        "api_call_id": call_id,
        "infrastructure_attempt_id": "INF-05" if script_exists or status else "INF-05",
        "cve_id": cve,
        "repetition": str(repetition),
        "script_path": f"generated_scripts/{cve}/rep{repetition:02d}/remediation.sh" if script_exists else "",
        "script_sha256": digest,
        "ami_id": ami,
        "instance_id": shared_instance if (script_exists or status or version_before) else "",
        "initial_state": str(before.get("result") or ""),
        "validation_recorded": validation_text,
        "execution_status": status,
        "version_before": version_before,
        "version_after": version_after,
        "recorded_remediation_success": "" if recorded is None else ("1" if recorded else "0"),
        "classification": classification,
        "classification_reason": reason,
        "source": "results/experiments.json",
    }


def write_csv(path: Path, fields: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            values = {field: row.get(field, "") for field in fields}
            if "gpt-6-luna" in "".join(values.values()):  # pragma: allowlist secret
                last = fields[-1]
                suffix = " // pragma: allowlist secret"
                if suffix not in values[last]:
                    values[last] = f"{values[last]}{suffix}"
            writer.writerow(values)


def _infra(
    attempt_id: str,
    number: str,
    timestamp: str,
    region: str,
    result: str,
    reason: str,
    created: str,
    cleanup: str,
    source: str,
    notes: str,
) -> dict[str, str]:
    return {
        "attempt_id": attempt_id,
        "attempt_number": number,
        "timestamp_utc": timestamp,
        "aws_region": region,
        "result": result,
        "failure_reason": reason,
        "resources_created": created,
        "cleanup_status": cleanup,
        "source": source,
        "notes": notes,
    }


def _ledger(root: Path) -> list[dict[str, Any]]:
    path = root / "results" / "experiments.json"
    if not path.is_file():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, list) else []


def _metadata(root: Path, repetition: Any) -> dict[str, Any] | None:
    if repetition is None:
        return None
    path = (
        root
        / "generated_scripts"
        / "CVE-2024-38428"
        / f"rep{int(repetition):02d}"
        / "metadata.json"
    )
    data = _read(path)
    return data if isinstance(data, dict) else None


def _read(path: Path) -> Any:
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _cell(value: Any) -> str:
    if value is None:
        return ""
    return str(value)
