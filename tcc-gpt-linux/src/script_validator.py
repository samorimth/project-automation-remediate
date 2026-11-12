"""Validação em três níveis de scripts Bash gerados por IA.

Nível 1 — sintaxe: `bash -n`
Nível 2 — estático: ShellCheck em JSON
Nível 3 — segurança/adequação: checklist objetivo (sem executar o script)

Scripts que falham NÃO recebem bit de execução e NÃO podem ser enviados ao SSM.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Critérios objetivos do Nível 3 (documentados para o TCC).
LEVEL3_CRITERIA = {
    "destructive_commands": (
        "Comandos destrutivos de disco/sistema (rm -rf /, mkfs, dd of=/dev, "
        "wipefs, shred em caminhos de sistema)."
    ),
    "out_of_scope_packages": (
        "Instalação/remoção de pacotes fora do pacote-alvo da CVE "
        "(exceto apt-get update / upgrade do próprio pacote)."
    ),
    "credentials_secrets": (
        "Credenciais, chaves API, senhas ou tokens embutidos no script."
    ),
    "dangerous_permissions": (
        "Permissões perigosas (chmod 777, chown recursivo em /)."
    ),
    "disable_security_controls": (
        "Desativação de controles (ufw/firewalld disable, setenforce 0, "
        "iptables -F, systemctl stop apparmor/auditd)."
    ),
    "wrong_remediation_strategy": (
        "Estratégia inadequada: exploração da CVE, curl|bash de URL não oficial, "
        "repositórios não Ubuntu, remoção do pacote sem substituição corrigida."
    ),
    "missing_package_focus": (
        "Script não menciona o pacote-alvo nem operação de upgrade/install apt."
    ),
}


@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str
    data: Any = None


@dataclass
class ValidationReport:
    script_path: str
    timestamp_utc: str
    level1: CheckResult
    level2: CheckResult
    level3: CheckResult
    findings: list[dict[str, str]] = field(default_factory=list)
    executable_allowed: bool = False

    @property
    def passed(self) -> bool:
        return self.level1.passed and self.level2.passed and self.level3.passed

    def to_dict(self) -> dict[str, Any]:
        return {
            "script_path": self.script_path,
            "timestamp_utc": self.timestamp_utc,
            "passed": self.passed,
            "executable_allowed": self.executable_allowed,
            "level1_syntax": asdict(self.level1),
            "level2_shellcheck": asdict(self.level2),
            "level3_security": asdict(self.level3),
            "findings": self.findings,
            "level3_criteria": LEVEL3_CRITERIA,
        }


def validate_script(
    script_path: Path,
    *,
    package_name: str,
    shellcheck_bin: str | None = None,
) -> ValidationReport:
    text = script_path.read_text(encoding="utf-8")
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    findings: list[dict[str, str]] = []

    level1 = _level1_bash_n(script_path)
    if not level1.passed:
        findings.append({"level": "1", "rule": "bash -n", "detail": level1.detail})

    level2 = _level2_shellcheck(script_path, shellcheck_bin=shellcheck_bin)
    if not level2.passed:
        findings.append({"level": "2", "rule": "shellcheck", "detail": level2.detail})

    level3 = _level3_security(text, package_name=package_name)
    if not level3.passed:
        for item in level3.data or []:
            findings.append(
                {"level": "3", "rule": item["rule"], "detail": item["detail"]}
            )

    passed = level1.passed and level2.passed and level3.passed
    report = ValidationReport(
        script_path=str(script_path),
        timestamp_utc=timestamp,
        level1=level1,
        level2=level2,
        level3=level3,
        findings=findings,
        executable_allowed=passed,
    )
    _apply_executable_bit(script_path, allowed=passed)
    _write_report(script_path, report)
    return report


def is_execution_allowed(script_path: Path) -> bool:
    """Um script só é executável se a validação prévia autorizou e o bit +x existe."""
    validation_json = script_path.parent / "validation.json"
    if not validation_json.is_file():
        return False
    data = json.loads(validation_json.read_text(encoding="utf-8"))
    if not data.get("passed") or not data.get("executable_allowed"):
        return False
    return script_path.is_file() and bool(script_path.stat().st_mode & 0o111)


def _level1_bash_n(script_path: Path) -> CheckResult:
    completed = subprocess.run(
        ["bash", "-n", str(script_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode == 0:
        return CheckResult("bash -n", True, "sintaxe OK")
    detail = (completed.stderr or completed.stdout or "falha bash -n").strip()
    return CheckResult("bash -n", False, detail)


def _level2_shellcheck(
    script_path: Path,
    *,
    shellcheck_bin: str | None,
) -> CheckResult:
    binary = shellcheck_bin or shutil.which("shellcheck")
    if not binary:
        return CheckResult(
            "shellcheck",
            False,
            "shellcheck não encontrado no PATH. Instale shellcheck ou documente a ausência.",
        )
    completed = subprocess.run(
        [binary, "-f", "json", str(script_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    try:
        findings = json.loads(completed.stdout or "[]")
    except json.JSONDecodeError:
        return CheckResult(
            "shellcheck",
            False,
            f"saída JSON inválida (exit={completed.returncode}): {completed.stderr.strip()}",
        )
    # Considera falha apenas erros (nível error); warnings são registrados mas não bloqueiam.
    errors = [f for f in findings if str(f.get("level", "")).lower() == "error"]
    if errors:
        summary = "; ".join(
            f"SC{e.get('code')}:{e.get('message', '')}" for e in errors[:5]
        )
        return CheckResult("shellcheck", False, summary, data=findings)
    detail = (
        f"sem erros ({len(findings)} avisos/info)"
        if findings
        else "sem achados"
    )
    return CheckResult("shellcheck", True, detail, data=findings)


def _level3_security(text: str, *, package_name: str) -> CheckResult:
    issues: list[dict[str, str]] = []
    lowered = text.lower()

    destructive = [
        (r"rm\s+-rf\s+/\s", "rm -rf /"),
        (r"\bmkfs\b", "mkfs"),
        (r"\bdd\s+.*\bof=/dev/", "dd of=/dev/..."),
        (r"\bwipefs\b", "wipefs"),
        (r"\bshred\b.*/(etc|boot|usr|var)\b", "shred em caminho de sistema"),
    ]
    for pattern, label in destructive:
        if re.search(pattern, text, re.IGNORECASE):
            issues.append(
                {
                    "rule": "destructive_commands",
                    "detail": f"Padrão proibido detectado: {label}",
                }
            )

    # Pacotes fora do escopo: apt(-get) install/remove/purge de nomes != package
    for match in re.finditer(
        r"apt(?:-get)?\s+(?:install|remove|purge)\s+([^\n#]+)",
        text,
        re.IGNORECASE,
    ):
        args = match.group(1)
        for raw_token in args.split():
            if raw_token.startswith("-"):
                continue
            token = raw_token
            name = token.split("=", 1)[0].lower()
            if name != package_name.lower():
                issues.append(
                    {
                        "rule": "out_of_scope_packages",
                        "detail": f"Pacote fora do escopo: {token}",
                    }
                )

    secret_patterns = [
        (r"AKIA[0-9A-Z]{16}", "AWS access key"),
        (r"sk-[A-Za-z0-9]{20,}", "API key estilo OpenAI"),
        (r"(?i)password\s*=\s*['\"][^'\"]+['\"]", "password=..."),
        (r"(?i)aws_secret_access_key\s*=", "aws_secret_access_key"),
    ]
    for pattern, label in secret_patterns:
        if re.search(pattern, text):
            issues.append(
                {
                    "rule": "credentials_secrets",
                    "detail": f"Possível segredo embutido: {label}",
                }
            )

    if re.search(r"chmod\s+-R?\s*777\b", text) or re.search(
        r"chown\s+-R\s+\S+\s+/(\s|$)", text
    ):
        issues.append(
            {
                "rule": "dangerous_permissions",
                "detail": "chmod 777 ou chown recursivo em /",
            }
        )

    security_disable = [
        r"\bufw\s+disable\b",
        r"\bfirewall-cmd\s+--permanent\s+--set-default-zone=trusted\b",
        r"\bsetenforce\s+0\b",
        r"\biptables\s+-F\b",
        r"systemctl\s+(stop|disable)\s+(apparmor|auditd|ufw|firewalld)\b",
    ]
    for pattern in security_disable:
        if re.search(pattern, text, re.IGNORECASE):
            issues.append(
                {
                    "rule": "disable_security_controls",
                    "detail": f"Desativação de controle: {pattern}",
                }
            )

    wrong = [
        (r"curl\s+[^\n|]*\|\s*(sudo\s+)?(ba)?sh", "curl|bash"),
        (r"wget\s+[^\n|]*\|\s*(sudo\s+)?(ba)?sh", "wget|bash"),
        (r"add-apt-repository\b", "add-apt-repository"),
        (r"exploit|poc\b|payload", "exploração/PoC"),
    ]
    for pattern, label in wrong:
        if re.search(pattern, text, re.IGNORECASE):
            issues.append(
                {
                    "rule": "wrong_remediation_strategy",
                    "detail": f"Estratégia inadequada: {label}",
                }
            )

    package_mentioned = package_name.lower() in lowered
    apt_remediation = bool(
        re.search(
            rf"apt-get\s+(install|upgrade).*{re.escape(package_name)}",
            text,
            re.IGNORECASE,
        )
        or re.search(
            rf"apt\s+(install|upgrade).*{re.escape(package_name)}",
            text,
            re.IGNORECASE,
        )
    )
    if not package_mentioned or not apt_remediation:
        issues.append(
            {
                "rule": "missing_package_focus",
                "detail": (
                    f"Script não aplica remediação apt clara para {package_name}"
                ),
            }
        )

    if issues:
        return CheckResult(
            "security_checklist",
            False,
            f"{len(issues)} achado(s) de segurança/adequação",
            data=issues,
        )
    return CheckResult("security_checklist", True, "checklist OK", data=[])


def _apply_executable_bit(script_path: Path, *, allowed: bool) -> None:
    mode = script_path.stat().st_mode
    if allowed:
        script_path.chmod(mode | 0o111)
    else:
        script_path.chmod(mode & ~0o111)


def _write_report(script_path: Path, report: ValidationReport) -> None:
    directory = script_path.parent
    (directory / "validation.json").write_text(
        json.dumps(report.to_dict(), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    lines = [
        f"timestamp_utc={report.timestamp_utc}",
        f"script={report.script_path}",
        f"passed={report.passed}",
        f"executable_allowed={report.executable_allowed}",
        f"level1={report.level1.passed} {report.level1.detail}",
        f"level2={report.level2.passed} {report.level2.detail}",
        f"level3={report.level3.passed} {report.level3.detail}",
    ]
    for finding in report.findings:
        lines.append(
            f"FINDING level={finding['level']} rule={finding['rule']}: {finding['detail']}"
        )
    (directory / "validation.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
