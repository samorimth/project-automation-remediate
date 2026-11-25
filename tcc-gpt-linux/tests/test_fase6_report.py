import csv
import json
from pathlib import Path

from src.fase6_report import generate_report

LEDGER = [
    {
        "cve_id": "CVE-2024-38428",
        "repetition": 1,
        "model": "gpt-4.1",
        "generation_latency_ms": 3370,
        "prompt_tokens": None,
        "completion_tokens": None,
        "total_tokens": None,
        "validation_passed": None,
        "execution_authorized": False,
        "execution_status": None,
        "version_before": None,
        "version_after": None,
        "remediation_success": None,
        "notes": "generate_error:RateLimitError: HTTP 429",
    },
    {
        "cve_id": "CVE-2024-38428",
        "repetition": 2,
        "model": "modelo-teste",
        "generation_latency_ms": 6201,
        "prompt_tokens": 10,
        "completion_tokens": 20,
        "total_tokens": 30,
        "validation_passed": None,
        "execution_authorized": False,
        "execution_status": None,
        "version_before": None,
        "version_after": None,
        "remediation_success": None,
        "notes": "generate_only",
    },
    {
        "cve_id": "CVE-2024-38428",
        "repetition": 2,
        "model": "modelo-teste",
        "generation_latency_ms": None,
        "prompt_tokens": None,
        "completion_tokens": None,
        "total_tokens": None,
        "validation_passed": False,
        "execution_authorized": False,
        "execution_status": None,
        "version_before": None,
        "version_after": None,
        "remediation_success": None,
        "notes": "validate",
    },
    {
        "cve_id": "CVE-2024-38428",
        "repetition": 2,
        "model": "modelo-teste",
        "generation_latency_ms": None,
        "prompt_tokens": None,
        "completion_tokens": None,
        "total_tokens": None,
        "validation_passed": True,
        "execution_authorized": False,
        "execution_status": None,
        "version_before": None,
        "version_after": None,
        "remediation_success": None,
        "notes": "validate",
    },
    {
        "cve_id": "CVE-2024-38428",
        "repetition": 2,
        "model": "modelo-teste",
        "generation_latency_ms": None,
        "prompt_tokens": None,
        "completion_tokens": None,
        "total_tokens": None,
        "validation_passed": True,
        "execution_authorized": True,
        "execution_status": "Success",
        "version_before": "1.21.4-1ubuntu4",
        "version_after": "1.21.4-1ubuntu4.5",
        "remediation_success": True,
        "notes": "execute",
    },
]

SCRIPT = """#!/usr/bin/env bash
set -euo pipefail
readonly PACKAGE="wget"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade "$PACKAGE" ||
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$PACKAGE"
INSTALLED="$(dpkg-query -W -f='${Version}' "$PACKAGE")"
dpkg --compare-versions "$INSTALLED" ge "1.21.4-1ubuntu4.1"
"""


def _write_fixture(root: Path, *, version_after: str = "1.21.4-1ubuntu4.5") -> None:
    ledger = json.loads(json.dumps(LEDGER))
    ledger[-1]["version_after"] = version_after
    results = root / "results"
    results.mkdir(parents=True)
    (results / "experiments.json").write_text(
        json.dumps(ledger, indent=2) + "\n",
        encoding="utf-8",
    )
    fields = list(ledger[0].keys())
    with (results / "experiments.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in ledger:
            writer.writerow({key: "" if value is None else value for key, value in row.items()})
    script_dir = root / "generated_scripts" / "CVE-2024-38428" / "rep02"
    script_dir.mkdir(parents=True)
    script = script_dir / "remediation.sh"
    script.write_text(SCRIPT, encoding="utf-8")
    import hashlib

    digest = hashlib.sha256(script.read_bytes()).hexdigest()
    (script_dir / "metadata.json").write_text(
        json.dumps(
            {
                "prompt_tokens": 10,
                "completion_tokens": 20,
                "total_tokens": 30,
                "latency_ms": 6201,
                "script_hash_sha256": digest,
            }
        ),
        encoding="utf-8",
    )
    (script_dir / "validation.json").write_text(
        json.dumps(
            {
                "passed": True,
                "level1_syntax": {"passed": True},
                "level2_shellcheck": {"passed": True, "data": [{"level": "info"}]},
                "level3_security": {"passed": True},
            }
        ),
        encoding="utf-8",
    )
    (script_dir / "validation.log").write_text("original\n", encoding="utf-8")
    (script_dir / "verify_before_execute.json").write_text(
        json.dumps({"installed_version": "1.21.4-1ubuntu4", "result": "vulneravel_por_versao"}),
        encoding="utf-8",
    )
    (script_dir / "verify_after_execute.json").write_text(
        json.dumps({"installed_version": version_after, "result": "corrigido_por_versao"}),
        encoding="utf-8",
    )
    (script_dir / "ssm-execute.json").write_text(
        json.dumps(
            {
                "status": "Success",
                "stdout": f"Unpacking wget ({version_after}) over (1.21.4-1ubuntu4)",
            }
        ),
        encoding="utf-8",
    )


def _rates(path: Path) -> dict[str, dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return {
            row["metric"]: row
            for row in csv.DictReader(handle)
            if row["section"] == "rate"
        }


def test_report_keeps_originals_and_separates_denominators(tmp_path: Path):
    _write_fixture(tmp_path)
    original = (tmp_path / "results" / "experiments.json").read_bytes()
    script = tmp_path / "generated_scripts" / "CVE-2024-38428" / "rep02" / "remediation.sh"
    script_bytes = script.read_bytes()
    log_bytes = (script.parent / "validation.log").read_bytes()

    assert generate_report(tmp_path) == 0
    assert (tmp_path / "results" / "experiments.json").read_bytes() == original
    assert script.read_bytes() == script_bytes
    assert (script.parent / "validation.log").read_bytes() == log_bytes
    assert (tmp_path / "results" / "fase6" / "revalidation" / "rep02" / "validation.json").is_file()

    rates = _rates(tmp_path / "results" / "summary.csv")
    assert rates["syntax_pass_among_generated_scripts"]["numerator"] == "1"
    assert rates["syntax_pass_among_generated_scripts"]["denominator"] == "1"
    assert rates["security_pass_among_recorded_validation_events"]["numerator"] == "1"
    assert rates["security_pass_among_recorded_validation_events"]["denominator"] == "2"
    assert rates["remediation_among_executions"]["numerator"] == "1"
    assert rates["remediation_among_executions"]["denominator"] == "1"
    assert rates["remediation_among_openai_calls"]["denominator"] == "2"
    for name in (
        "taxa_correcao_sintatica.png",
        "analise_estatica.png",
        "aprovacao_seguranca.png",
        "taxa_remediacao.png",
        "tempo_geracao.png",
        "consumo_tokens.png",
        "cost.png",
    ):
        assert (tmp_path / "results" / "charts" / name).stat().st_size > 0
    for name in (
        "syntax_success.png",
        "remediation_success.png",
        "security_approval.png",
        "generation_time.png",
        "token_usage.png",
    ):
        assert not (tmp_path / "results" / "charts" / name).exists()
    architecture = tmp_path / "docs" / "arquitetura"
    assert not (architecture / "fluxo_experimental.mmd").exists()
    assert not (architecture / "fluxo_experimental.svg").exists()
    assert not (architecture / "fluxo_experimental.png").exists()


def test_report_flags_a_version_mismatch_without_rewriting_the_ledger(tmp_path: Path):
    _write_fixture(tmp_path)
    verify = (
        tmp_path
        / "generated_scripts"
        / "CVE-2024-38428"
        / "rep02"
        / "verify_after_execute.json"
    )
    verify.write_text(
        json.dumps({"installed_version": "9.9.9", "result": "corrigido_por_versao"}),
        encoding="utf-8",
    )
    original = (tmp_path / "results" / "experiments.json").read_bytes()
    assert generate_report(tmp_path) == 1
    assert (tmp_path / "results" / "experiments.json").read_bytes() == original
    audit = json.loads((tmp_path / "results" / "fase6" / "auditoria.json").read_text())
    assert any("version_after" in item for item in audit["hard_inconsistencies"])
