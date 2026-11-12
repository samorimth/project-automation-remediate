"""Validação independente before/after da remediação (versão do pacote)."""

from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from .config import Settings
from .prompt_builder import ScenarioMetadata


@dataclass
class VersionCheck:
    package_name: str
    installed_version: str | None
    fixed_version: str
    compare: str
    result: str
    raw_stdout: str
    raw_stderr: str
    ssm_command_id: str | None
    ssm_status: str
    timestamp_utc: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_version_check_script(package_name: str, fixed_version: str) -> str:
    return f"""#!/usr/bin/env bash
set -euo pipefail
PKG="{package_name}"
FIXED="{fixed_version}"
INSTALLED="$(dpkg -s "$PKG" 2>/dev/null | sed -n 's/^Version: //p' || true)"
echo "installed=$INSTALLED"
echo "fixed=$FIXED"
if [[ -z "$INSTALLED" ]]; then
  echo "resultado=pacote_ausente"
  exit 2
fi
if dpkg --compare-versions "$INSTALLED" ge "$FIXED"; then
  echo "resultado=corrigido_por_versao"
  exit 0
fi
if dpkg --compare-versions "$INSTALLED" lt "$FIXED"; then
  echo "resultado=vulneravel_por_versao"
  exit 0
fi
echo "resultado=inconclusivo"
exit 3
"""


def check_package_version(
    *,
    settings: Settings,
    instance_id: str,
    scenario: ScenarioMetadata,
    phase: str,
    output_dir: Path | None = None,
    timeout_seconds: int = 120,
) -> VersionCheck:
    """Consulta a versão do pacote via SSM, independente do script GPT."""
    script = build_version_check_script(scenario.package_name, scenario.fixed_version)
    client = boto3.client("ssm", region_name=settings.aws_region)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    command_id: str | None = None
    status = "not_sent"
    stdout = ""
    stderr = ""

    try:
        response = client.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Comment=f"tcc-fase3-verify-{phase}:{scenario.cve_id}",
            Parameters={"commands": [script]},
            TimeoutSeconds=timeout_seconds,
        )
        command_id = response["Command"]["CommandId"]
        status, stdout, stderr = _wait_invocation(
            client, command_id, instance_id, timeout_seconds
        )
    except (ClientError, BotoCoreError) as exc:
        status = "Error"
        stderr = str(exc)

    installed = _parse_kv(stdout, "installed")
    result_label = _parse_kv(stdout, "resultado") or "inconclusivo"
    compare = "ge" if result_label == "corrigido_por_versao" else "lt"

    check = VersionCheck(
        package_name=scenario.package_name,
        installed_version=installed or None,
        fixed_version=scenario.fixed_version,
        compare=compare,
        result=result_label,
        raw_stdout=stdout,
        raw_stderr=stderr,
        ssm_command_id=command_id,
        ssm_status=status,
        timestamp_utc=timestamp,
    )
    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / f"verify_{phase}.json").write_text(
            json.dumps(check.to_dict(), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    return check


def remediation_succeeded(before: VersionCheck, after: VersionCheck) -> bool:
    return (
        before.result == "vulneravel_por_versao"
        and after.result == "corrigido_por_versao"
        and after.ssm_status == "Success"
    )


def _wait_invocation(
    client: Any,
    command_id: str,
    instance_id: str,
    timeout_seconds: int,
) -> tuple[str, str, str]:
    deadline = time.time() + timeout_seconds
    status = "Pending"
    stdout = ""
    stderr = ""
    while time.time() < deadline:
        time.sleep(2.0)
        try:
            invocation = client.get_command_invocation(
                CommandId=command_id,
                InstanceId=instance_id,
            )
        except client.exceptions.InvocationDoesNotExist:
            continue
        status = invocation.get("Status", status)
        if status in {"Success", "Cancelled", "TimedOut", "Failed"}:
            stdout = invocation.get("StandardOutputContent") or ""
            stderr = invocation.get("StandardErrorContent") or ""
            break
    return status, stdout, stderr


def _parse_kv(stdout: str, key: str) -> str | None:
    match = re.search(rf"(?m)^{re.escape(key)}=(.*)$", stdout)
    if not match:
        return None
    value = match.group(1).strip()
    return value or None
