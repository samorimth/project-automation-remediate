"""Execução remota via AWS Systems Manager Run Command.

Somente scripts previamente validados e autorizados com a frase
AUTORIZO_EXECUCAO_SCRIPT_IA podem ser enviados.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from .aws_manager import AuthorizationError
from .config import EXECUTE_AUTHORIZATION_PHRASE, Settings
from .script_validator import is_execution_allowed


@dataclass
class SsmRunResult:
    command_id: str
    instance_id: str
    status: str
    stdout: str
    stderr: str
    response_code: int | None
    timestamp_utc: str
    script_path: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def require_execute_authorization(authorize: str | None) -> None:
    if authorize != EXECUTE_AUTHORIZATION_PHRASE:
        raise AuthorizationError(
            "A execução do script gerado por IA não foi realizada. "
            f"Informe --authorize {EXECUTE_AUTHORIZATION_PHRASE}."
        )


def execute_script(
    *,
    settings: Settings,
    instance_id: str,
    script_path: Path,
    authorize: str | None,
    timeout_seconds: int = 600,
    poll_seconds: float = 3.0,
) -> SsmRunResult:
    require_execute_authorization(authorize)
    if not is_execution_allowed(script_path):
        raise AuthorizationError(
            "Script sem validação aprovada ou sem permissão de execução. "
            "Rode `validate` com sucesso antes de `execute`."
        )

    script_text = script_path.read_text(encoding="utf-8")
    client = boto3.client("ssm", region_name=settings.aws_region)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    try:
        response = client.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Comment=f"tcc-fase3:{script_path.name}",
            Parameters={"commands": [script_text]},
            TimeoutSeconds=timeout_seconds,
        )
        command_id = response["Command"]["CommandId"]
    except (ClientError, BotoCoreError) as exc:
        raise RuntimeError(f"Falha ao enviar Run Command: {exc}") from exc

    status = "Pending"
    stdout = ""
    stderr = ""
    response_code: int | None = None
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        time.sleep(poll_seconds)
        try:
            invocation = client.get_command_invocation(
                CommandId=command_id,
                InstanceId=instance_id,
            )
        except client.exceptions.InvocationDoesNotExist:
            continue
        except (ClientError, BotoCoreError) as exc:
            raise RuntimeError(f"Falha ao consultar invocação SSM: {exc}") from exc

        status = invocation.get("Status", status)
        if status in {"Success", "Cancelled", "TimedOut", "Failed"}:
            stdout = invocation.get("StandardOutputContent") or ""
            stderr = invocation.get("StandardErrorContent") or ""
            response_code = invocation.get("ResponseCode")
            break

    result = SsmRunResult(
        command_id=command_id,
        instance_id=instance_id,
        status=status,
        stdout=stdout,
        stderr=stderr,
        response_code=response_code,
        timestamp_utc=timestamp,
        script_path=str(script_path),
    )
    evidence_dir = script_path.parent
    (evidence_dir / "ssm-execute.json").write_text(
        json.dumps(result.to_dict(), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return result


def resolve_instance_id(hint: str | None, evidence_before: Path | None = None) -> str:
    if hint:
        return hint
    if evidence_before and evidence_before.is_file():
        data = json.loads(evidence_before.read_text(encoding="utf-8"))
        instance_id = data.get("instance_id")
        if instance_id:
            return instance_id
    raise ValueError(
        "instance_id não informado. Use --instance-id ou scenario com evidence/before.json."
    )
