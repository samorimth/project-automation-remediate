"""Fase 6: consolida evidências já gravadas.

Lê `results/experiments.json`, os metadados e as evidências de SSM.
Não chama a OpenAI, não chama a AWS e não reescreve o ledger experimental
nem os scripts gerados.
"""

from __future__ import annotations

import csv
import hashlib
import json
import sys
import textwrap
from pathlib import Path
from typing import Any

from .config import LAB_ROOT
from .script_validator import validate_script

SUMMARY_FIELDS = [
    "section",
    "cve_id",
    "repetition",
    "metric",
    "value",
    "numerator",
    "denominator",
    "unit",
    "source",
    "notes",
]

CHARTS = (
    "taxa_correcao_sintatica.png",
    "analise_estatica.png",
    "aprovacao_seguranca.png",
    "taxa_remediacao.png",
    "tempo_geracao.png",
    "consumo_tokens.png",
    "cost.png",
)

PROTECTED_RELATIVE = (
    "results/experiments.json",
    "results/experiments.csv",
    "results/CVE-2024-38428",
    "generated_scripts",
    "scenarios",
)


def generate_report(lab_root: Path | None = None) -> int:
    """Gera summary.csv, gráficos e a auditoria. Devolve 0 ou 1."""
    root = lab_root or LAB_ROOT
    before = _snapshot(root)
    summary_path = root / "results" / "summary.csv"
    charts_dir = root / "results" / "charts"
    review_root = root / "results" / "fase6" / "revalidation"
    audit_path = root / "results" / "fase6" / "auditoria.json"

    try:
        ledger = _load_ledger(root / "results" / "experiments.json")
    except (FileNotFoundError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    rows, audit = _build(root, ledger)
    reviews = _revalidate(root, review_root)
    rows.extend(_review_rows(reviews))
    audit["revalidation"] = reviews
    audit["hard_inconsistencies"] = _hard_inconsistencies(root, ledger, reviews)

    summary_path.parent.mkdir(parents=True, exist_ok=True)
    _write_csv(summary_path, rows)
    _write_separated_ledgers(root)
    _write_revalidation_json(root, reviews)
    charts_dir.mkdir(parents=True, exist_ok=True)
    _write_charts(charts_dir, rows)
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    audit_path.write_text(
        json.dumps(audit, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    changed = _changed(root, before)
    if changed:
        raise RuntimeError(
            "A consolidação alterou evidência protegida: " + ", ".join(changed)
        )

    print(f"summary.csv: {summary_path}")
    for name in CHARTS:
        print(f"gráfico: {charts_dir / name}")
    print(f"auditoria: {audit_path}")
    print(f"revalidação: {review_root}")
    hard = audit["hard_inconsistencies"]
    print(f"inconsistências numéricas: {len(hard)}")
    for item in hard:
        print(f"- {item}")
    return 1 if hard else 0


def _build(root: Path, ledger: list[dict[str, Any]]) -> tuple[list[dict[str, str]], dict[str, Any]]:
    rows: list[dict[str, str]] = []
    observations: list[str] = []
    cve = "CVE-2024-38428"

    for index, event in enumerate(ledger, start=1):
        notes = str(event.get("notes") or "")
        kind = _event_kind(notes)
        repetition = event.get("repetition")
        source = f"results/experiments.json#row{index}"
        rows.append(
            _row(
                kind,
                cve,
                repetition,
                "recorded_event",
                notes.split(";", 1)[0],
                source=source,
                notes=notes,
            )
        )
        if event.get("generation_latency_ms") is not None:
            rows.append(
                _row(
                    kind,
                    cve,
                    repetition,
                    "generation_latency_ms",
                    event["generation_latency_ms"],
                    unit="ms",
                    source=source,
                )
            )
        for token_field in ("prompt_tokens", "completion_tokens", "total_tokens"):
            if event.get(token_field) is not None:
                rows.append(
                    _row(
                        kind,
                        cve,
                        repetition,
                        token_field,
                        event[token_field],
                        unit="tokens",
                        source=source,
                    )
                )
        if kind == "validation_event" and event.get("validation_passed") is not None:
            rows.append(
                _row(
                    "validation_event",
                    cve,
                    repetition,
                    "validation_passed",
                    _bool_cell(event["validation_passed"]),
                    source=source,
                )
            )
        if kind == "execution":
            for field in (
                "execution_status",
                "version_before",
                "version_after",
                "remediation_success",
            ):
                if event.get(field) is not None:
                    value = event[field]
                    if isinstance(value, bool):
                        value = _bool_cell(value)
                    rows.append(
                        _row("execution", cve, repetition, field, value, source=source)
                    )

    unknown_keys = sorted(
        {
            key
            for event in ledger
            for key in event
            if key
            not in {
                "cve_id",
                "repetition",
                "model",
                "generation_latency_ms",
                "prompt_tokens",
                "completion_tokens",
                "total_tokens",
                "validation_passed",
                "execution_authorized",
                "execution_status",
                "version_before",
                "version_after",
                "remediation_success",
                "notes",
            }
        }
    )
    if unknown_keys:
        observations.append(
            "experiments.json contém chaves fora do esquema "
            f"({', '.join(unknown_keys)}). O leitor JSON mantém a última "
            "ocorrência quando a chave está duplicada. Os indicadores usam "
            "somente os campos do esquema."
        )

    redacted = [
        event.get("repetition")
        for event in ledger
        if event.get("model") == "[REDACTED]"
    ]
    if redacted:
        observations.append(
            "O campo model das repetições "
            + ", ".join(str(item) for item in sorted(set(redacted)))
            + " está gravado como [REDACTED]. O nome configurado não é "
            "recuperável desse JSON. Não foi reescrito."
        )

    api_calls = [event for event in ledger if _event_kind(str(event.get("notes") or "")) == "openai_call"]
    scripts = _existing_scripts(root, cve)
    validations = [
        event for event in ledger if str(event.get("notes") or "") == "validate"
    ]
    executions = [
        event for event in ledger if str(event.get("notes") or "") == "execute"
    ]
    syntax_ok = 0
    static_ok = 0
    security_final_ok = 0
    for repetition, script in scripts:
        preserved = _read_json(script.parent / "validation.json")
        if not preserved:
            observations.append(
                f"rep{repetition:02d} tem remediation.sh e não tem validation.json."
            )
            continue
        level1 = bool(preserved.get("level1_syntax", {}).get("passed"))
        level2 = bool(preserved.get("level2_shellcheck", {}).get("passed"))
        level3 = bool(preserved.get("level3_security", {}).get("passed"))
        info = [
            item
            for item in preserved.get("level2_shellcheck", {}).get("data") or []
            if str(item.get("level", "")).lower() != "error"
        ]
        errors = [
            item
            for item in preserved.get("level2_shellcheck", {}).get("data") or []
            if str(item.get("level", "")).lower() == "error"
        ]
        syntax_ok += int(level1)
        static_ok += int(level2)
        security_final_ok += int(level3)
        source = f"generated_scripts/{cve}/rep{repetition:02d}/validation.json"
        rows.append(_row("validation_preserved", cve, repetition, "level1_syntax_passed", _bool_cell(level1), source=source))
        rows.append(_row("validation_preserved", cve, repetition, "level2_shellcheck_passed", _bool_cell(level2), source=source))
        rows.append(_row("validation_preserved", cve, repetition, "level2_errors", len(errors), unit="count", source=source))
        rows.append(_row("validation_preserved", cve, repetition, "level2_info_or_warning", len(info), unit="count", source=source))
        rows.append(_row("validation_preserved", cve, repetition, "level3_security_passed", _bool_cell(level3), source=source))

    passed_events = sum(1 for event in validations if event.get("validation_passed") is True)
    failed_events = sum(1 for event in validations if event.get("validation_passed") is False)
    proved = sum(1 for event in executions if event.get("remediation_success") is True)
    api_ok = sum(1 for event in api_calls if not str(event.get("notes") or "").startswith("generate_error"))
    api_fail = len(api_calls) - api_ok
    n_scripts = len(scripts)

    rows.extend(
        [
            _rate("syntax_pass_among_generated_scripts", syntax_ok, n_scripts, "validation.json preservado; a chamada sem script fica de fora", "generated_scripts/CVE-2024-38428/rep*/validation.json"),
            _rate("static_analysis_pass_among_generated_scripts", static_ok, n_scripts, "passou sem erro ShellCheck; avisos info permanecem contados à parte", "generated_scripts/CVE-2024-38428/rep*/validation.json"),
            _rate("security_pass_among_recorded_validation_events", passed_events, len(validations), "inclui a primeira reprovação da repetição 2", "results/experiments.json"),
            _rate("security_pass_among_preserved_final_validations", security_final_ok, n_scripts, "último validation.json de cada script; a primeira reprovação foi sobrescrita", "generated_scripts/CVE-2024-38428/rep*/validation.json"),
            _rate("remediation_among_executions", proved, len(executions), "remediation_success verdadeiro no ledger e conferido na evidência SSM", "results/experiments.json"),
            _rate("remediation_among_openai_calls", proved, len(api_calls), "a chamada HTTP 429 não gerou script e não entra como remediação", "results/experiments.json"),
        ]
    )
    rows.append(_row("openai_call", cve, "", "calls_total", len(api_calls), unit="count", source="results/experiments.json"))
    rows.append(_row("openai_call", cve, "", "calls_http_429", api_fail, unit="count", source="results/experiments.json"))
    rows.append(_row("openai_call", cve, "", "calls_with_script", api_ok, unit="count", source="results/experiments.json"))
    rows.append(_row("validation_event", cve, "", "events_failed", failed_events, unit="count", source="results/experiments.json"))

    _append_provisioning(root, rows, observations)
    _append_non_calls(root, rows, observations)
    _append_prepare(root, rows, observations)

    audit = {
        "cve_id": cve,
        "ledger_rows": len(ledger),
        "openai_calls": len(api_calls),
        "scripts_generated": n_scripts,
        "validation_events": len(validations),
        "validation_events_passed": passed_events,
        "validation_events_failed": failed_events,
        "executions": len(executions),
        "remediations_proved": proved,
        "observations": observations,
    }
    return rows, audit


def _append_provisioning(root: Path, rows: list[dict[str, str]], observations: list[str]) -> None:
    blocked = _read_json(root / "results" / "CVE-2024-38428" / "execucao_bloqueada.json")
    before = _read_json(root / "scenarios" / "CVE-2024-38428" / "evidence" / "before.json")
    cleanup = _read_json(root / "scenarios" / "CVE-2024-38428" / "evidence" / "cleanup-fase3.json")
    if isinstance(blocked, dict):
        rows.append(
            _row(
                "aws_provisioning",
                "CVE-2024-38428",
                "",
                "attempt_4_apply",
                "not_run",
                source="results/CVE-2024-38428/execucao_bloqueada.json",
                notes=str(blocked.get("reason") or ""),
            )
        )
    if isinstance(before, dict):
        rows.append(
            _row(
                "aws_provisioning",
                "CVE-2024-38428",
                "",
                "attempt_5_apply",
                "succeeded" if before.get("terraform_apply_succeeded") else "failed",
                source="scenarios/CVE-2024-38428/evidence/before.json",
                notes=(
                    f"resources_added={before.get('resources_added')}; "
                    f"instance={before.get('instance_id')}"
                ),
            )
        )
    if isinstance(cleanup, list):
        removed = sum(1 for item in cleanup if item.get("ok") is True)
        rows.append(
            _row(
                "aws_provisioning",
                "CVE-2024-38428",
                "",
                "cleanup_items_ok",
                removed,
                unit="count",
                source="scenarios/CVE-2024-38428/evidence/cleanup-fase3.json",
            )
        )
    observations.append(
        "As tentativas de provisionamento 1 a 3 aparecem só na narrativa de "
        "scenarios/CVE-2024-38428/evidence/STATUS.md. Não há JSON próprio "
        "delas. A tentativa 4 tem JSON de sonda SCP, com apply não executado. "
        "A tentativa 5 tem apply bem-sucedido em before.json."
    )


def _append_non_calls(root: Path, rows: list[dict[str, str]], observations: list[str]) -> None:
    blocked = _read_json(
        root / "scenarios" / "CVE-2024-38428" / "evidence" / "fase3_generate_blocked.json"
    )
    status = _read_json(root / "results" / "CVE-2024-38428" / "fase3_generate_status.json")
    if isinstance(blocked, dict) and blocked.get("pipeline", {}).get("generate") == "not_run":
        rows.append(
            _row(
                "openai_not_called",
                "CVE-2024-38428",
                "",
                "blocked_without_api_key",
                1,
                unit="count",
                source="scenarios/CVE-2024-38428/evidence/fase3_generate_blocked.json",
                notes="generate not_run; não entra no denominador de chamadas à API",
            )
        )
    if isinstance(status, dict):
        sent = status.get("execute", {}).get("ssm_command_sent")
        rows.append(
            _row(
                "execution_refused_locally",
                "CVE-2024-38428",
                status.get("generate", {}).get("repetition"),
                "ssm_command_sent",
                _bool_cell(bool(sent)),
                source="results/CVE-2024-38428/fase3_generate_status.json",
                notes=str(status.get("execute", {}).get("detail") or ""),
            )
        )
        observations.append(
            "A repetição 1 tem validate e execute recusados em "
            "fase3_generate_status.json. O ledger só guarda a linha generate_error. "
            "Nenhum comando SSM foi enviado nessa repetição."
        )


def _append_prepare(root: Path, rows: list[dict[str, str]], observations: list[str]) -> None:
    evidence = root / "scenarios" / "CVE-2024-38428" / "evidence"
    for name, repetition in (("ssm-prepare-rep03.json", 3), ("ssm-prepare-rep04.json", 4)):
        payload = _read_json(evidence / name)
        if not isinstance(payload, dict):
            observations.append(f"Evidência ausente: {name}")
            continue
        stdout = str(payload.get("stdout") or payload.get("stdout_tail") or "")
        restored = "versao_instalada=1.21.4-1ubuntu4" in stdout and "vulneravel_por_versao" in stdout
        rows.append(
            _row(
                "baseline_restore",
                "CVE-2024-38428",
                repetition,
                "prepare_restored_vulnerable_version",
                _bool_cell(restored and payload.get("status") == "Success"),
                source=f"scenarios/CVE-2024-38428/evidence/{name}",
                notes=f"command_id={payload.get('command_id')}",
            )
        )
    observations.append(
        "A repetição 2 partiu do estado vulnerável já provado na Fase 2. "
        "prepare.sh --apply restaurou wget 1.21.4-1ubuntu4 antes das "
        "repetições 3 e 4, depois que a execução anterior tinha instalado "
        "1.21.4-1ubuntu4.5."
    )


def _revalidate(root: Path, review_root: Path) -> list[dict[str, Any]]:
    reviews: list[dict[str, Any]] = []
    for repetition, script in _existing_scripts(root, "CVE-2024-38428"):
        preserved_path = script.parent / "validation.json"
        preserved = _read_json(preserved_path) or {}
        before_script = script.read_bytes()
        before_validation = preserved_path.read_bytes() if preserved_path.is_file() else None
        before_log = script.parent / "validation.log"
        before_log_bytes = before_log.read_bytes() if before_log.is_file() else None
        destination = review_root / f"rep{repetition:02d}"
        report = validate_script(script, package_name="wget", persist_dir=destination)
        if script.read_bytes() != before_script:
            raise RuntimeError(f"revalidação alterou {script}")
        if before_validation is not None and preserved_path.read_bytes() != before_validation:
            raise RuntimeError(f"revalidação alterou {preserved_path}")
        if before_log_bytes is not None and before_log.read_bytes() != before_log_bytes:
            raise RuntimeError(f"revalidação alterou {before_log}")
        info = [
            item
            for item in (report.level2.data or [])
            if str(item.get("level", "")).lower() != "error"
        ]
        reviews.append(
            {
                "repetition": repetition,
                "script": str(script.relative_to(root)),
                "review_dir": str(destination.relative_to(root)),
                "level1_passed": report.level1.passed,
                "level2_passed": report.level2.passed,
                "level2_info_or_warning": len(info),
                "level3_passed": report.level3.passed,
                "passed": report.passed,
                "preserved_passed": preserved.get("passed"),
                "matches_preserved_passed": report.passed == preserved.get("passed"),
                "note": (
                    "Revisão com o validador atual. Não substitui o validation.json "
                    "da época da execução nem a primeira reprovação da repetição 2."
                ),
            }
        )
    return reviews


def _review_rows(reviews: list[dict[str, Any]]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for review in reviews:
        source = review["review_dir"] + "/validation.json"
        rows.append(
            _row(
                "revalidation_fase6",
                "CVE-2024-38428",
                review["repetition"],
                "passed",
                _bool_cell(bool(review["passed"])),
                source=source,
                notes=review["note"],
            )
        )
        rows.append(
            _row(
                "revalidation_fase6",
                "CVE-2024-38428",
                review["repetition"],
                "matches_preserved_passed",
                _bool_cell(bool(review["matches_preserved_passed"])),
                source=source,
            )
        )
    return rows


def _hard_inconsistencies(
    root: Path,
    ledger: list[dict[str, Any]],
    reviews: list[dict[str, Any]],
) -> list[str]:
    problems: list[str] = []
    csv_path = root / "results" / "experiments.csv"
    if csv_path.is_file():
        with csv_path.open(encoding="utf-8", newline="") as handle:
            csv_rows = list(csv.DictReader(handle))
        if len(csv_rows) != len(ledger):
            problems.append(
                f"experiments.csv tem {len(csv_rows)} linhas e experiments.json tem {len(ledger)}."
            )
        else:
            for index, (csv_row, event) in enumerate(zip(csv_rows, ledger), start=1):
                if str(csv_row.get("repetition")) != str(event.get("repetition")):
                    problems.append(f"linha {index}: repetição diverge entre CSV e JSON")
                if str(csv_row.get("generation_latency_ms") or "") != _cell(event.get("generation_latency_ms")):
                    problems.append(f"linha {index}: latência diverge entre CSV e JSON")
                if str(csv_row.get("version_after") or "") != _cell(event.get("version_after")):
                    problems.append(f"linha {index}: version_after diverge entre CSV e JSON")

    for repetition, script in _existing_scripts(root, "CVE-2024-38428"):
        meta = _read_json(script.parent / "metadata.json") or {}
        digest = hashlib.sha256(script.read_bytes()).hexdigest()
        if meta.get("script_hash_sha256") != digest:
            problems.append(f"rep{repetition:02d}: hash do remediation.sh difere do metadata")
        generate_rows = [
            event
            for event in ledger
            if event.get("repetition") == repetition
            and str(event.get("notes") or "").startswith("generate_only")
        ]
        if generate_rows:
            event = generate_rows[0]
            for field in ("prompt_tokens", "completion_tokens", "total_tokens"):
                if event.get(field) != meta.get(field):
                    problems.append(
                        f"rep{repetition:02d}: {field} do ledger ({event.get(field)}) "
                        f"difere do metadata ({meta.get(field)})"
                    )
            if event.get("generation_latency_ms") != meta.get("latency_ms"):
                problems.append(f"rep{repetition:02d}: latência do ledger difere do metadata")
        execute_rows = [
            event
            for event in ledger
            if event.get("repetition") == repetition and event.get("notes") == "execute"
        ]
        if not execute_rows:
            continue
        event = execute_rows[-1]
        before = _read_json(script.parent / "verify_before_execute.json") or {}
        after = _read_json(script.parent / "verify_after_execute.json") or {}
        if before.get("installed_version") != event.get("version_before"):
            problems.append(f"rep{repetition:02d}: version_before difere de verify_before_execute.json")
        if after.get("installed_version") != event.get("version_after"):
            problems.append(f"rep{repetition:02d}: version_after difere de verify_after_execute.json")
        if after.get("result") != "corrigido_por_versao" and event.get("remediation_success") is True:
            problems.append(f"rep{repetition:02d}: sucesso no ledger sem corrigido_por_versao")
        ssm = _read_json(script.parent / "ssm-execute.json") or {}
        stdout = str(ssm.get("stdout") or "")
        version_after = str(event.get("version_after") or "")
        version_before = str(event.get("version_before") or "")
        if version_after and f"({version_after})" not in stdout:
            problems.append(f"rep{repetition:02d}: stdout do SSM não contém a versão depois")
        if version_before and f"over ({version_before})" not in stdout:
            problems.append(f"rep{repetition:02d}: stdout do SSM não contém a versão antes")
        if ssm.get("status") != event.get("execution_status"):
            problems.append(f"rep{repetition:02d}: status SSM difere do ledger")

    for review in reviews:
        if review["matches_preserved_passed"] is not True:
            problems.append(
                f"rep{review['repetition']:02d}: a revalidação atual não reproduz "
                "o passed do validation.json preservado"
            )
    return problems


def _write_charts(charts_dir: Path, rows: list[dict[str, str]]) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    def save(name: str, title: str, categories: list[str], series: list[tuple[str, list[float]]], ylabel: str, caption: str) -> None:
        fig, ax = plt.subplots(figsize=(8.4, 4.8))
        count = len(categories)
        width = 0.36 if len(series) > 1 else 0.55
        positions = list(range(count))
        peak = 0.0
        for index, (label, values) in enumerate(series):
            offset = (index - (len(series) - 1) / 2) * width
            bars = ax.bar(
                [pos + offset for pos in positions],
                values,
                width=width,
                label=label,
            )
            peak = max(peak, max(values, default=0))
            for bar, value in zip(bars, values):
                ax.text(
                    bar.get_x() + bar.get_width() / 2,
                    bar.get_height(),
                    _format_bar(value),
                    ha="center",
                    va="bottom",
                    fontsize=8,
                )
        ax.set_title(title)
        ax.set_ylabel(ylabel)
        ax.set_xticks(positions, categories)
        ax.set_ylim(0, peak * 1.25 if peak else 1)
        if len(series) > 1:
            ax.legend()
        ax.set_xlabel("\n".join(textwrap.wrap(caption.replace("$", r"\$"), width=90)), fontsize=8)
        fig.tight_layout()
        fig.savefig(charts_dir / name, dpi=140)
        plt.close(fig)

    scripts = _metric_map(rows, "validation_preserved", "level1_syntax_passed")
    info = _metric_map(rows, "validation_preserved", "level2_info_or_warning")
    errors = _metric_map(rows, "validation_preserved", "level2_errors")
    security_events = [
        (row["repetition"], row["value"])
        for row in rows
        if row["section"] == "validation_event" and row["metric"] == "validation_passed"
    ]
    latencies = [
        (row["repetition"], float(row["value"]))
        for row in rows
        if row["section"] == "openai_call" and row["metric"] == "generation_latency_ms"
    ]
    prompt = _metric_map(rows, "openai_call", "prompt_tokens")
    completion = _metric_map(rows, "openai_call", "completion_tokens")

    syntax_pass = sum(1 for value in scripts.values() if value == "1")
    syntax_fail = sum(1 for value in scripts.values() if value == "0")
    no_script = _single(rows, "openai_call", "calls_http_429")
    save(
        "taxa_correcao_sintatica.png",
        "Correção sintática (bash -n) da CVE-2024-38428",
        ["Scripts aprovados", "Scripts reprovados", "Chamadas sem script"],
        [("Contagem", [syntax_pass, syntax_fail, no_script])],
        "Quantidade",
        "Fonte: validation.json preservado e experiments.json. Denominador dos scripts: os três remediation.sh. A chamada HTTP 429 não gerou script.",
    )
    labels = [f"Rep. {rep}" for rep in sorted(info)]
    save(
        "analise_estatica.png",
        "ShellCheck nos três scripts gerados",
        labels,
        [
            ("Erros bloqueantes", [float(errors[rep]) for rep in sorted(errors)]),
            ("Avisos info", [float(info[rep]) for rep in sorted(info)]),
        ],
        "Achados ShellCheck",
        "Fonte: validation.json preservado em 12 de novembro de 2026. Erro bloqueia; info não bloqueia. A primeira validação da repetição 2 não está neste arquivo.",
    )
    seen: dict[str, int] = {}
    security_labels: list[str] = []
    for repetition, _value in security_events:
        seen[repetition] = seen.get(repetition, 0) + 1
        security_labels.append(f"Rep. {repetition}, {seen[repetition]}ª")
    save(
        "aprovacao_seguranca.png",
        "Eventos de validação registrados no ledger",
        security_labels,
        [("Aprovado (1) ou reprovado (0)", [float(value) for _, value in security_events])],
        "Resultado",
        "Fonte: results/experiments.json. A repetição 2 tem dois eventos: o primeiro reprovado e o segundo aprovado. O validation.json preservado é só o segundo.",
    )
    proved = _rate_pair(rows, "remediation_among_executions")
    calls = _rate_pair(rows, "remediation_among_openai_calls")
    save(
        "taxa_remediacao.png",
        "Remediação comprovada da CVE-2024-38428",
        ["Execuções SSM", "Chamadas à API"],
        [
            ("Comprovadas", [proved[0], calls[0]]),
            ("Demais casos do denominador", [proved[1] - proved[0], calls[1] - calls[0]]),
        ],
        "Quantidade",
        "Fonte: experiments.json e verify_after_execute.json. Comprovada significa versão >= 1.21.4-1ubuntu4.1, observada 1.21.4-1ubuntu4.5.",
    )
    save(
        "tempo_geracao.png",
        "Latência das chamadas à API",
        [f"Rep. {rep}" for rep, _ in latencies],
        [("Latência", [value for _, value in latencies])],
        "Latência (ms)",
        "Fonte: results/experiments.json. A repetição 1 é a chamada que recebeu HTTP 429 e não devolveu script.",
    )
    token_reps = sorted(set(prompt) & set(completion))
    from .historical_ledger import estimate_generation_cost_usd

    costs = []
    for rep in token_reps:
        costs.append(
            float(
                estimate_generation_cost_usd(int(float(prompt[rep])), int(float(completion[rep])))
                or 0
            )
        )
    save(
        "cost.png",
        "Custo estimado das gerações com tokens devolvidos",
        [f"Rep. {rep}" for rep in token_reps],
        [("Estimativa (USD)", costs)],
        "USD estimados",
        "Tabela pública de US$ 0,10 por milhão de tokens de entrada e US$ 0,50 por milhão de saída. Não é fatura. A chamada HTTP 429 não devolveu tokens e não entra neste gráfico.",
    )
    save(
        "consumo_tokens.png",
        "Tokens das gerações que devolveram script",
        [f"Rep. {rep}" for rep in token_reps],
        [
            ("Entrada", [float(prompt[rep]) for rep in token_reps]),
            ("Saída", [float(completion[rep]) for rep in token_reps]),
        ],
        "Tokens",
        "Fonte: results/experiments.json. A chamada HTTP 429 não devolveu contagem de tokens e não entra neste gráfico.",
    )


def _load_ledger(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise FileNotFoundError(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("experiments.json não é uma lista")
    return data


def _existing_scripts(root: Path, cve: str) -> list[tuple[int, Path]]:
    found: list[tuple[int, Path]] = []
    base = root / "generated_scripts" / cve
    if not base.is_dir():
        return found
    for directory in sorted(base.glob("rep*")):
        script = directory / "remediation.sh"
        if script.is_file() and script.stat().st_size > 0:
            found.append((int(directory.name.removeprefix("rep")), script))
    return found


def _event_kind(notes: str) -> str:
    if notes.startswith("generate_error") or notes.startswith("generate_only"):
        return "openai_call"
    if notes == "validate":
        return "validation_event"
    if notes == "execute":
        return "execution"
    return "other"


def _row(
    section: str,
    cve: str,
    repetition: Any,
    metric: str,
    value: Any,
    *,
    numerator: Any = "",
    denominator: Any = "",
    unit: str = "",
    source: str = "",
    notes: str = "",
) -> dict[str, str]:
    return {
        "section": section,
        "cve_id": cve,
        "repetition": "" if repetition is None else str(repetition),
        "metric": metric,
        "value": _cell(value),
        "numerator": _cell(numerator),
        "denominator": _cell(denominator),
        "unit": unit,
        "source": source,
        "notes": notes,
    }


def _rate(
    metric: str,
    numerator: int,
    denominator: int,
    notes: str,
    source: str,
) -> dict[str, str]:
    value = "" if denominator == 0 else f"{numerator / denominator:.4f}"
    return _row(
        "rate",
        "CVE-2024-38428",
        "",
        metric,
        value,
        numerator=numerator,
        denominator=denominator,
        unit="ratio",
        source=source,
        notes=notes,
    )


def _write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=SUMMARY_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def _read_json(path: Path) -> Any:
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _cell(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _bool_cell(value: bool) -> str:
    return "1" if value else "0"


def _metric_map(rows: list[dict[str, str]], section: str, metric: str) -> dict[str, str]:
    return {
        row["repetition"]: row["value"]
        for row in rows
        if row["section"] == section and row["metric"] == metric and row["repetition"]
    }


def _single(rows: list[dict[str, str]], section: str, metric: str) -> float:
    for row in rows:
        if row["section"] == section and row["metric"] == metric:
            return float(row["value"] or 0)
    return 0


def _rate_pair(rows: list[dict[str, str]], metric: str) -> tuple[float, float]:
    for row in rows:
        if row["section"] == "rate" and row["metric"] == metric:
            return float(row["numerator"] or 0), float(row["denominator"] or 0)
    return 0, 0


def _format_bar(value: float) -> str:
    if abs(value) < 1 and value != 0:
        return f"{value:.6f}"
    if float(value).is_integer():
        return str(int(value))
    return f"{value:.0f}"


def _snapshot(root: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for relative in PROTECTED_RELATIVE:
        path = root / relative
        if path.is_file():
            hashes[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
        elif path.is_dir():
            for child in path.rglob("*"):
                if child.is_file():
                    hashes[str(child)] = hashlib.sha256(child.read_bytes()).hexdigest()
    return hashes


def _changed(root: Path, before: dict[str, str]) -> list[str]:
    changed: list[str] = []
    for path, digest in before.items():
        file = Path(path)
        if not file.is_file() or hashlib.sha256(file.read_bytes()).hexdigest() != digest:
            changed.append(str(file.relative_to(root)))
    return changed


def _write_separated_ledgers(root: Path) -> None:
    from .historical_ledger import (
        API_FIELDS,
        INFRASTRUCTURE_FIELDS,
        RUN_FIELDS,
        api_calls,
        experimental_runs,
        infrastructure_attempts,
        write_csv,
    )

    results = root / "results"
    write_csv(results / "infrastructure_attempts.csv", INFRASTRUCTURE_FIELDS, infrastructure_attempts(root))
    write_csv(results / "api_calls.csv", API_FIELDS, api_calls(root))
    write_csv(results / "experimental_runs.csv", RUN_FIELDS, experimental_runs(root))


def _write_revalidation_json(root: Path, reviews: list[dict[str, Any]]) -> None:
    status = _read_json(root / "results" / "CVE-2024-38428" / "fase3_rep02_status.json")
    first_pass = None
    if isinstance(status, dict):
        recorded = status.get("validate") or {}
        first_pass = {
            "repetition": 2,
            "passed": False,
            "exit_code": recorded.get("first_pass_exit_code"),
            "reason": recorded.get("first_pass_reason"),
            "validation_json": "sobrescrito pela segunda passagem",
            "source": "results/CVE-2024-38428/fase3_rep02_status.json",
        }
    payload = {
        "note": (
            "Revalidação com o validador atual. Não substitui validation.json "
            "nem o booleano histórico de remediation_success."
        ),
        "original_first_pass_rep02": first_pass,
        "scripts": reviews,
    }
    path = root / "results" / "revalidation.json"
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

