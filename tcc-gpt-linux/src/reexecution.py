"""Reexecução controlada da CVE-2024-38428.

Uma EC2 nova, criada da mesma AMI privada, executa um único script original.
Este módulo não chama a API da OpenAI e não grava dentro de generated_scripts.
A infraestrutura compartilhada só é destruída com AUTORIZO_DESTRUIR_RECURSOS.
"""

from __future__ import annotations

import argparse
import atexit
import base64
import hashlib
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from .aws_manager import AuthorizationError
from .config import (
    APPLY_AUTHORIZATION_PHRASE,
    DESTROY_AUTHORIZATION_PHRASE,
    EXECUTE_AUTHORIZATION_PHRASE,
    LAB_ROOT,
    TERRAFORM_DIR,
)
from .fresh_instance import InstanceLedger, ReferenceAmi, reject_restore_baseline
from .script_validator import validate_script

REGION = "us-east-2"
CVE_ID = "CVE-2024-38428"
PUBLIC_BASE_AMI = "ami-096d6538c463eb1db"
PACKAGE = "wget"
VULNERABLE_VERSION = "1.21.4-1ubuntu4"
FIXED_VERSION = "1.21.4-1ubuntu4.1"
PACKAGE_SHA256 = "1d078bf2a22c2c6da84788818ebf055a10f5f6b5ea629f1dd0dd11660b51def6"
UBUNTU_CODENAME = "noble"
UBUNTU_VERSION_ID = "24.04"
INSTANCE_TYPE = "t3.small"
EXPERIMENT_ID = "reexec-wget"
REPETITIONS = ("rep02", "rep03", "rep04")
EVIDENCE_ROOT = LAB_ROOT / "results" / "reexecution" / CVE_ID
STATE_PATH = EVIDENCE_ROOT / "state.json"
SCRIPTS_ROOT = LAB_ROOT / "generated_scripts" / CVE_ID
PREPARE_SCRIPT = LAB_ROOT / "scenarios" / CVE_ID / "prepare.sh"


def assert_evidence_dir(path: Path) -> None:
    """Recusa gravar por cima dos scripts e das evidências históricas."""
    resolved = path.resolve()
    protected = (
        (LAB_ROOT / "generated_scripts").resolve(),
        (LAB_ROOT / "evidence_archive").resolve(),
        (LAB_ROOT / "results" / "experiments.json").resolve(),
        (LAB_ROOT / "results" / "experiments.csv").resolve(),
        (LAB_ROOT / "results" / CVE_ID).resolve(),
    )
    for item in protected:
        if resolved == item or item in resolved.parents:
            raise AuthorizationError(f"Destino protegido: {resolved}")
    root = (LAB_ROOT / "results" / "reexecution").resolve()
    if resolved != root and root not in resolved.parents:
        raise AuthorizationError(f"A reexecução só grava em {root}")


def classify_reexecution(
    *,
    validation_passed: bool,
    initial_vulnerable: bool,
    executed: bool,
    version_after: str | None,
    functional_ok: bool | None,
    fresh_instance: bool,
) -> tuple[str, str]:
    if not validation_passed:
        return "BLOQUEADO", "O validador atual recusou o script original."
    if not initial_vulnerable:
        return (
            "INCONCLUSIVO",
            "O estado inicial não era wget 1.21.4-1ubuntu4 no Ubuntu 24.04. O script não foi executado.",
        )
    if not executed:
        return "NAO_EXECUTADO", "O script não foi enviado à instância."
    if not fresh_instance:
        return "INCONCLUSIVO", "A instância não era exclusiva desta repetição."
    if version_after is None or functional_ok is None:
        return "INCONCLUSIVO", "A verificação posterior ou o teste funcional não foi coletado."
    if functional_ok and _version_at_least(version_after, FIXED_VERSION):
        return (
            "SUCESSO",
            "Estado inicial vulnerável, versão posterior atende o mínimo oficial e o wget funcional respondeu.",
        )
    if not functional_ok:
        return "FALHA", "O teste funcional do wget não teve êxito depois da execução."
    return "FALHA", "A versão posterior permanece abaixo de 1.21.4-1ubuntu4.1."


def _version_at_least(installed: str, minimum: str) -> bool:
    """Confere a versão com o dpkg local. A instância continua sendo a fonte do número."""
    completed = subprocess.run(
        ["dpkg", "--compare-versions", installed, "ge", minimum],
        check=False,
        capture_output=True,
    )
    if completed.returncode == 0:
        return True
    if completed.returncode == 1:
        return False
    raise RuntimeError("dpkg --compare-versions indisponível para classificar a reexecução.")


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    assert_evidence_dir(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _load_state() -> dict[str, Any]:
    if not STATE_PATH.is_file():
        return {"repetitions": {}}
    return json.loads(STATE_PATH.read_text(encoding="utf-8"))


def _save_state(state: dict[str, Any]) -> None:
    state["updated_at_utc"] = _utc_now()
    _write_json(STATE_PATH, state)


def _bash_wrapper(script_text: str, args: str = "") -> str:
    encoded = base64.b64encode(script_text.encode("utf-8")).decode("ascii")
    suffix = f" {args}" if args else ""
    return (
        f"printf '%s' '{encoded}' | base64 -d > /tmp/tcc-reexec.sh && "
        f"bash /tmp/tcc-reexec.sh{suffix}"
    )


def _clients() -> tuple[Any, Any]:
    return (
        boto3.client("ec2", region_name=REGION),
        boto3.client("ssm", region_name=REGION),
    )


def run_shell(
    ssm: Any,
    instance_id: str,
    script_text: str,
    comment: str,
    timeout: int = 600,
    args: str = "",
) -> dict[str, Any]:
    started = time.monotonic()
    timestamp = _utc_now()
    response = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Comment=comment[:100],
        Parameters={"commands": [_bash_wrapper(script_text, args)]},
        TimeoutSeconds=timeout,
    )
    command_id = response["Command"]["CommandId"]
    deadline = time.time() + timeout
    status = "Pending"
    stdout = ""
    stderr = ""
    response_code = None
    while time.time() < deadline:
        time.sleep(3)
        try:
            invocation = ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ssm.exceptions.InvocationDoesNotExist:
            continue
        except (ClientError, BotoCoreError) as exc:
            raise RuntimeError(f"Falha ao consultar SSM {command_id}: {exc}") from exc
        status = invocation.get("Status", status)
        if status in {"Success", "Cancelled", "TimedOut", "Failed", "Cancelling"}:
            stdout = invocation.get("StandardOutputContent") or ""
            stderr = invocation.get("StandardErrorContent") or ""
            response_code = invocation.get("ResponseCode")
            break
    return {
        "command_id": command_id,
        "instance_id": instance_id,
        "status": status,
        "stdout": stdout,
        "stderr": stderr,
        "response_code": response_code,
        "timestamp_utc": timestamp,
        "duration_seconds": round(time.monotonic() - started, 3),
        "comment": comment,
    }


def _parse_lines(stdout: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in stdout.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() in {
            "id",
            "version_id",
            "codename",
            "pretty",
            "package",
            "version",
            "compare",
            "exit_code",
            "bytes",
            "first_line",
            "scanner",
            "file_exit",
        }:
            values[key.strip()] = value.strip()
    return values


INSPECT_SCRIPT = f"""#!/usr/bin/env bash
set -u
. /etc/os-release
echo "id=${{ID:-}}"
echo "version_id=${{VERSION_ID:-}}"
echo "codename=${{VERSION_CODENAME:-}}"
echo "pretty=${{PRETTY_NAME:-}}"
echo "package={PACKAGE}"
echo "version=$(dpkg-query -W -f='${{Version}}' {PACKAGE} 2>/dev/null || true)"
if dpkg --compare-versions "$(dpkg-query -W -f='${{Version}}' {PACKAGE} 2>/dev/null || echo 0)" lt "{FIXED_VERSION}"; then
  echo "compare=lt"
else
  echo "compare=ge"
fi
dpkg-query -W {PACKAGE} || true
apt-cache policy {PACKAGE} || true
"""

FUNCTIONAL_SCRIPT = """#!/usr/bin/env bash
set -u
out=$(mktemp)
wget -O "$out" --timeout=20 file:///etc/os-release
code=$?
echo "exit_code=$code"
echo "bytes=$(wc -c < "$out" | tr -d ' ')"
echo "first_line=$(head -n 1 "$out")"
rm -f "$out"
if command -v oscap >/dev/null 2>&1; then
  echo "scanner=oscap_presente_nao_executado_como_prova"
else
  echo "scanner=indisponivel"
fi
wget --version | head -n 1 || true
"""

HARDEN_SCRIPT = """#!/usr/bin/env bash
set -u
systemctl disable --now unattended-upgrades.service >/dev/null 2>&1 || true
systemctl disable --now apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1 || true
mkdir -p /etc/cloud/cloud.cfg.d
cat > /etc/cloud/cloud.cfg.d/99-tcc-lab.cfg <<'EOF'
package_update: false
package_upgrade: false
EOF
echo "harden=ok"
"""


def _initial_ok(parsed: dict[str, str]) -> bool:
    return (
        parsed.get("id") == "ubuntu"
        and parsed.get("version_id") == UBUNTU_VERSION_ID
        and parsed.get("codename") == UBUNTU_CODENAME
        and parsed.get("version") == VULNERABLE_VERSION
        and parsed.get("compare") == "lt"
    )


def terraform_apply(experiment_id: str = EXPERIMENT_ID) -> dict[str, Any]:
    init = subprocess.run(
        ["terraform", "init", "-input=false"],
        cwd=TERRAFORM_DIR,
        check=False,
        text=True,
    )
    if init.returncode != 0:
        raise RuntimeError("terraform init falhou.")
    apply = subprocess.run(
        [
            "terraform",
            "apply",
            "-input=false",
            "-auto-approve",
            "-var",
            f"aws_region={REGION}",
            "-var",
            "enable_nat_gateway=true",
            "-var",
            "enable_execution=false",
            "-var",
            "enable_ssm_vpc_endpoints=false",
            "-var",
            "instance_count=0",
            "-var",
            "max_instances=3",
            "-var",
            "max_simultaneous_instances=1",
            "-var",
            f"experiment_id={experiment_id}",
            "-var",
            "environment=lab",
            "-var",
            f"instance_type={INSTANCE_TYPE}",
        ],
        cwd=TERRAFORM_DIR,
        check=False,
        text=True,
    )
    if apply.returncode != 0:
        raise RuntimeError("terraform apply da infraestrutura compartilhada falhou.")
    output = subprocess.run(
        ["terraform", "output", "-json"],
        cwd=TERRAFORM_DIR,
        check=False,
        text=True,
        capture_output=True,
    )
    if output.returncode != 0:
        raise RuntimeError(output.stderr)
    raw = json.loads(output.stdout)
    return {key: value.get("value") for key, value in raw.items()}


def _block_devices(ec2: Any, ami_id: str) -> list[dict[str, Any]]:
    image = ec2.describe_images(ImageIds=[ami_id])["Images"][0]
    mappings: list[dict[str, Any]] = []
    for device in image.get("BlockDeviceMappings") or []:
        ebs = device.get("Ebs") or {}
        snapshot_id = ebs.get("SnapshotId")
        if not snapshot_id:
            continue
        mappings.append(
            {
                "DeviceName": device["DeviceName"],
                "Ebs": {
                    "SnapshotId": snapshot_id,
                    "VolumeSize": max(int(ebs.get("VolumeSize") or 8), 20),
                    "VolumeType": "gp3",
                    "DeleteOnTermination": True,
                    "Encrypted": True,
                },
            }
        )
    if not mappings:
        raise RuntimeError(f"A AMI {ami_id} não tem snapshot de disco raiz.")
    return mappings


def launch_instance(
    ec2: Any,
    outputs: dict[str, Any],
    ami_id: str,
    name: str,
    role: str,
    experiment_id: str = EXPERIMENT_ID,
) -> str:
    response = ec2.run_instances(
        ImageId=ami_id,
        InstanceType=INSTANCE_TYPE,
        MinCount=1,
        MaxCount=1,
        SubnetId=outputs["private_subnet_id"],
        SecurityGroupIds=[outputs["lab_security_group_id"]],
        IamInstanceProfile={"Name": outputs["instance_profile_name"]},
        UserData=(TERRAFORM_DIR / "user_data.sh").read_text(encoding="utf-8"),
        MetadataOptions={
            "HttpTokens": "required",
            "HttpEndpoint": "enabled",
            "HttpPutResponseHopLimit": 1,
        },
        BlockDeviceMappings=_block_devices(ec2, ami_id),
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [
                    {"Key": "Name", "Value": name},
                    {"Key": "Project", "Value": "tcc-gpt-linux"},
                    {"Key": "ExperimentId", "Value": experiment_id},
                    {"Key": "Environment", "Value": "lab"},
                    {"Key": "Purpose", "Value": "tcc-lab"},
                    {"Key": "Role", "Value": role},
                ],
            }
        ],
    )
    return response["Instances"][0]["InstanceId"]


def wait_ssm(ec2: Any, ssm: Any, instance_id: str, timeout: int = 480) -> None:
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 5, "MaxAttempts": 40})
    deadline = time.time() + timeout
    while time.time() < deadline:
        info = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )
        items = info.get("InstanceInformationList") or []
        if items and items[0].get("PingStatus") == "Online":
            return
        time.sleep(10)
    raise RuntimeError(f"SSM não ficou Online para {instance_id}.")


def terminate_instance(ec2: Any, instance_id: str) -> dict[str, Any]:
    ec2.terminate_instances(InstanceIds=[instance_id])
    ec2.get_waiter("instance_terminated").wait(
        InstanceIds=[instance_id],
        WaiterConfig={"Delay": 10, "MaxAttempts": 40},
    )
    return {"instance_id": instance_id, "terminated": True, "timestamp_utc": _utc_now()}


def _ami_is_private(ec2: Any, ami_id: str) -> bool:
    attribute = ec2.describe_image_attribute(ImageId=ami_id, Attribute="launchPermission")
    return not attribute.get("LaunchPermissions")


def bake_ami(ec2: Any, ssm: Any, outputs: dict[str, Any], state: dict[str, Any]) -> str:
    if state.get("ami_id"):
        ami_id = str(state["ami_id"])
        print(f"AMI já registrada: {ami_id}", flush=True)
        ec2.get_waiter("image_available").wait(ImageIds=[ami_id], WaiterConfig={"Delay": 20, "MaxAttempts": 90})
        if not state.get("baker_terminated") and state.get("baker_instance_id"):
            cleanup = terminate_instance(ec2, str(state["baker_instance_id"]))
            state["baker_terminated"] = True
            _save_state(state)
            _write_json(EVIDENCE_ROOT / "ami" / "baker-cleanup.json", cleanup)
        return ami_id
    instance_id = state.get("baker_instance_id")
    if not instance_id or state.get("baker_terminated"):
        instance_id = launch_instance(ec2, outputs, PUBLIC_BASE_AMI, "tcc-lab-reexec-baker", "baker")
        state["baker_instance_id"] = instance_id
        state["baker_terminated"] = False
        _save_state(state)
    wait_ssm(ec2, ssm, instance_id)
    prepare = PREPARE_SCRIPT.read_text(encoding="utf-8")
    prepared = run_shell(
        ssm,
        instance_id,
        prepare,
        "tcc-reexec-prepare-baker",
        timeout=900,
        args="--apply",
    )
    _write_json(EVIDENCE_ROOT / "ami" / "prepare.json", prepared)
    if prepared["status"] != "Success":
        raise RuntimeError("prepare.sh --apply na instância auxiliar falhou. Nenhum script de remediação foi executado.")
    hardened = run_shell(ssm, instance_id, HARDEN_SCRIPT, "tcc-reexec-harden-baker")
    _write_json(EVIDENCE_ROOT / "ami" / "harden.json", hardened)
    inspected = run_shell(ssm, instance_id, INSPECT_SCRIPT, "tcc-reexec-inspect-baker")
    _write_json(EVIDENCE_ROOT / "ami" / "before-image.json", inspected)
    parsed = _parse_lines(inspected["stdout"])
    if not _initial_ok(parsed):
        raise RuntimeError(f"A instância auxiliar não ficou no estado vulnerável esperado: {parsed}")
    image = ec2.create_image(
        InstanceId=instance_id,
        Name=f"tcc-lab-wget-{VULNERABLE_VERSION}-{_utc_now().replace(':', '').replace('-', '')}",
        Description=(
            f"{CVE_ID} Ubuntu {UBUNTU_VERSION_ID} {PACKAGE} {VULNERABLE_VERSION} "
            f"corrigida_minima {FIXED_VERSION} sha256 {PACKAGE_SHA256}"
        ),
        NoReboot=False,
        TagSpecifications=[
            {
                "ResourceType": "image",
                "Tags": [
                    {"Key": "Name", "Value": "tcc-lab-reference-cve-2024-38428"},
                    {"Key": "Project", "Value": "tcc-gpt-linux"},
                    {"Key": "ExperimentId", "Value": EXPERIMENT_ID},
                    {"Key": "Cve", "Value": CVE_ID},
                    {"Key": "Package", "Value": PACKAGE},
                    {"Key": "VulnerableVersion", "Value": VULNERABLE_VERSION},
                    {"Key": "FixedVersion", "Value": FIXED_VERSION},
                ],
            }
        ],
    )
    ami_id = image["ImageId"]
    state["ami_id"] = ami_id
    _save_state(state)
    print(f"AMI criada, aguardando disponibilidade: {ami_id}", flush=True)
    ec2.get_waiter("image_available").wait(ImageIds=[ami_id], WaiterConfig={"Delay": 20, "MaxAttempts": 90})
    private = _ami_is_private(ec2, ami_id)
    record = {
        "ami_id": ami_id,
        "private": private,
        "ubuntu_release": UBUNTU_VERSION_ID,
        "codename": UBUNTU_CODENAME,
        "package": PACKAGE,
        "vulnerable_version": VULNERABLE_VERSION,
        "fixed_version": FIXED_VERSION,
        "cve": CVE_ID,
        "scenario_id": CVE_ID,
        "package_sha256": PACKAGE_SHA256,
        "created_at_utc": _utc_now(),
        "source_public_ami": PUBLIC_BASE_AMI,
        "baker_instance_id": instance_id,
        "inspect": parsed,
    }
    ReferenceAmi(
        ami_id=ami_id,
        cve_id=CVE_ID,
        ubuntu_release=UBUNTU_VERSION_ID,
        package_name=PACKAGE,
        vulnerable_version=VULNERABLE_VERSION,
        fixed_version=FIXED_VERSION,
        package_sha256=PACKAGE_SHA256,
        scenario_id=CVE_ID,
        created_at_utc=record["created_at_utc"],
        private=private,
    ).assert_record()
    _write_json(EVIDENCE_ROOT / "ami" / "reference.json", record)
    cleanup = terminate_instance(ec2, instance_id)
    state["ami_id"] = ami_id
    state["baker_terminated"] = True
    state["reference"] = record
    _save_state(state)
    _write_json(EVIDENCE_ROOT / "ami" / "baker-cleanup.json", cleanup)
    return ami_id


def _script_for(repetition: str) -> Path:
    path = SCRIPTS_ROOT / repetition / "remediation.sh"
    if not path.is_file():
        raise FileNotFoundError(path)
    return path


def run_repetition(
    ec2: Any,
    ssm: Any,
    outputs: dict[str, Any],
    ami_id: str,
    repetition: str,
    ledger: InstanceLedger,
    authorize_execute: str,
) -> dict[str, Any]:
    if authorize_execute != EXECUTE_AUTHORIZATION_PHRASE:
        raise AuthorizationError("Execução recusada.")
    reject_restore_baseline("ami de referência")
    script_path = _script_for(repetition)
    original = script_path.read_bytes()
    script_text = original.decode("utf-8")
    digest = hashlib.sha256(original).hexdigest()
    destination = EVIDENCE_ROOT / repetition
    review = validate_script(script_path, package_name=PACKAGE, persist_dir=destination / "validation-review")
    if script_path.read_bytes() != original:
        raise AuthorizationError("O script original foi alterado durante a validação.")
    validation_passed = bool(review.passed)
    instance_id = ""
    record: dict[str, Any] = {
        "experiment_id": f"REEXEC-{CVE_ID}-{repetition}",
        "set": "reexecucao_controlada",
        "cve_id": CVE_ID,
        "repetition": repetition,
        "script_path": str(script_path.relative_to(LAB_ROOT)),
        "script_sha256": digest,
        "ami_id": ami_id,
        "instance_id": "",
        "validation_passed": validation_passed,
    }
    try:
        instance_id = launch_instance(
            ec2,
            outputs,
            ami_id,
            f"tcc-lab-reexec-{repetition}",
            repetition,
        )
        record["instance_id"] = instance_id
        ledger.open_instance(instance_id, ami_id, repetition)
        print(f"{repetition}: instância {instance_id}", flush=True)
        wait_ssm(ec2, ssm, instance_id)
        before = run_shell(ssm, instance_id, INSPECT_SCRIPT, f"tcc-reexec-before-{repetition}")
        _write_json(destination / "before.json", before)
        parsed_before = _parse_lines(before["stdout"])
        record["initial_state"] = parsed_before
        initial_ok = before["status"] == "Success" and _initial_ok(parsed_before)
        executed = False
        execution = None
        after_version = None
        functional_ok = None
        if validation_passed and initial_ok:
            execution = run_shell(
                ssm,
                instance_id,
                script_text,
                f"tcc-reexec-execute-{repetition}",
                timeout=900,
            )
            _write_json(destination / "ssm-execute.json", execution)
            executed = True
            after = run_shell(ssm, instance_id, INSPECT_SCRIPT, f"tcc-reexec-after-{repetition}")
            _write_json(destination / "after.json", after)
            functional = run_shell(ssm, instance_id, FUNCTIONAL_SCRIPT, f"tcc-reexec-functional-{repetition}")
            _write_json(destination / "functional.json", functional)
            parsed_after = _parse_lines(after["stdout"])
            parsed_functional = _parse_lines(functional["stdout"])
            after_version = parsed_after.get("version")
            functional_ok = (
                functional["status"] == "Success"
                and parsed_functional.get("exit_code") == "0"
                and int(parsed_functional.get("bytes") or "0") > 0
            )
            record["version_after"] = after_version
            record["functional"] = parsed_functional
            record["execution_status"] = execution["status"]
            record["execution_response_code"] = execution["response_code"]
        elif not initial_ok:
            record["execution_status"] = "not_sent"
        classification, reason = classify_reexecution(
            validation_passed=validation_passed,
            initial_vulnerable=initial_ok,
            executed=executed,
            version_after=after_version,
            functional_ok=functional_ok,
            fresh_instance=True,
        )
        record["classification"] = classification
        record["classification_reason"] = reason
        record["version_before"] = parsed_before.get("version")
        _write_markdown(destination / "evidence.md", record, before, execution)
        _write_json(destination / "classification.json", record)
        return record
    finally:
        if instance_id:
            cleanup = terminate_instance(ec2, instance_id)
            try:
                ledger.close_instance(instance_id)
            except Exception:
                ledger.remember_closed(instance_id)
            record["cleanup"] = cleanup
            _write_json(destination / "cleanup.json", cleanup)
            if record.get("classification"):
                _write_json(destination / "classification.json", record)


def _functional_description(record: dict[str, Any]) -> str:
    """Descreve o teste funcional a partir do conjunto e dos campos já gravados."""
    functional = record.get("functional")
    if not isinstance(functional, dict):
        functional = {}
    if record.get("set") == "reexecucao_http_local":
        return _http_functional_description(functional)
    return _file_functional_description(functional)


def _observed_bits(functional: dict[str, Any]) -> str:
    observed: list[str] = []
    if functional.get("exit_code") not in (None, ""):
        observed.append(f"código {functional['exit_code']}")
    if functional.get("bytes") not in (None, ""):
        observed.append(f"{functional['bytes']} bytes")
    if functional.get("first_line") not in (None, ""):
        observed.append(f"primeira linha `{functional['first_line']}`")
    if not observed:
        return ""
    return ", com " + ", ".join(observed)


def _http_functional_description(functional: dict[str, Any]) -> str:
    file_exit = ""
    if functional.get("file_exit") not in (None, ""):
        file_exit = f", que terminou com código {functional['file_exit']}"
    return (
        "O critério funcional desta repetição foi "
        "`wget -O <arquivo temporário> --timeout=20 http://127.0.0.1:9876/lab`"
        f"{_observed_bits(functional)}. "
        "O mesmo procedimento também executou "
        "`wget -O <arquivo temporário> --timeout=10 file:///etc/os-release`"
        f"{file_exit}. Essa sonda não compõe o critério."
    )


def _file_functional_description(functional: dict[str, Any]) -> str:
    return (
        "O teste funcional foi "
        "`wget -O <arquivo temporário> --timeout=20 file:///etc/os-release`"
        f"{_observed_bits(functional)}."
    )


def _write_markdown(path: Path, record: dict[str, Any], before: dict[str, Any], execution: dict[str, Any] | None) -> None:
    assert_evidence_dir(path)
    lines = [
        f"# {record['experiment_id']}",
        "",
        f"- Horário UTC do before: {before.get('timestamp_utc')}",
        f"- AMI: {record['ami_id']}",
        f"- Instância: {record['instance_id']}",
        f"- Script SHA-256: {record['script_sha256']}",
        f"- Versão inicial: {record.get('version_before')}",
        f"- Versão posterior: {record.get('version_after')}",
        f"- Execução: {record.get('execution_status')}",
        f"- Classificação: {record['classification']}",
        f"- Motivo: {record['classification_reason']}",
        "",
        _functional_description(record),
        "Não houve teste de exploração da CVE.",
        "",
    ]
    if execution:
        lines.append(f"Comando SSM: {execution.get('command_id')}")
        lines.append(f"Código de saída: {execution.get('response_code')}")
        lines.append(f"Duração observada no cliente: {execution.get('duration_seconds')} s")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _terminate_open_instances() -> None:
    try:
        ec2 = boto3.client("ec2", region_name=REGION)
        response = ec2.describe_instances(
            Filters=[
                {"Name": "tag:ExperimentId", "Values": [EXPERIMENT_ID]},
                {
                    "Name": "instance-state-name",
                    "Values": ["pending", "running", "stopping", "stopped"],
                },
            ]
        )
        ids = [
            item["InstanceId"]
            for reservation in response["Reservations"]
            for item in reservation["Instances"]
        ]
        if ids:
            print(f"Encerrando instâncias ainda ligadas: {', '.join(ids)}", flush=True)
            ec2.terminate_instances(InstanceIds=ids)
    except (ClientError, BotoCoreError) as exc:
        print(f"Não foi possível encerrar instâncias no encerramento: {exc}", flush=True)


def run(authorize_paid: str, authorize_execute: str) -> int:
    if authorize_paid != APPLY_AUTHORIZATION_PHRASE:
        raise AuthorizationError("Apply recusado.")
    if authorize_execute != EXECUTE_AUTHORIZATION_PHRASE:
        raise AuthorizationError("Execução recusada.")
    atexit.register(_terminate_open_instances)

    def _stop(signum: int, _frame: object) -> None:
        print(f"Sinal {signum}: encerrando instâncias da reexecução.", flush=True)
        _terminate_open_instances()
        raise SystemExit(1)

    import signal

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    EVIDENCE_ROOT.mkdir(parents=True, exist_ok=True)
    state = _load_state()
    print("Aplicando a infraestrutura compartilhada em us-east-2.", flush=True)
    outputs = terraform_apply()
    state["outputs"] = {
        "vpc_id": outputs.get("vpc_id"),
        "private_subnet_id": outputs.get("private_subnet_id"),
        "lab_security_group_id": outputs.get("lab_security_group_id"),
        "instance_profile_name": outputs.get("instance_profile_name"),
        "aws_region": REGION,
    }
    _save_state(state)
    ec2, ssm = _clients()
    ami_id = bake_ami(ec2, ssm, outputs, state)
    ledger = InstanceLedger(expected_ami_id=ami_id, max_simultaneous=1)
    ledger.remember_closed(str(state.get("baker_instance_id") or ""))
    for previous in (state.get("repetitions") or {}).values():
        ledger.remember_closed(str(previous.get("instance_id") or ""))
    rows = []
    for repetition in REPETITIONS:
        previous = (state.get("repetitions") or {}).get(repetition)
        if previous and previous.get("cleanup", {}).get("terminated") and previous.get("classification"):
            rows.append(previous)
            continue
        row = run_repetition(ec2, ssm, outputs, ami_id, repetition, ledger, authorize_execute)
        state.setdefault("repetitions", {})[repetition] = row
        _save_state(state)
        rows.append(row)
    summary = EVIDENCE_ROOT / "experimental_runs.csv"
    assert_evidence_dir(summary)
    header = (
        "experiment_id,set,cve_id,repetition,script_sha256,ami_id,instance_id,"
        "version_before,version_after,execution_status,classification\n"
    )
    body = []
    for row in rows:
        body.append(
            ",".join(
                [
                    row["experiment_id"],
                    row["set"],
                    row["cve_id"],
                    row["repetition"],
                    row["script_sha256"],
                    row["ami_id"],
                    row["instance_id"],
                    str(row.get("version_before") or ""),
                    str(row.get("version_after") or ""),
                    str(row.get("execution_status") or ""),
                    row["classification"],
                ]
            )
        )
    summary.write_text(header + "\n".join(body) + "\n", encoding="utf-8")
    print(json.dumps({"ami_id": ami_id, "runs": rows}, ensure_ascii=False, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Reexecução controlada. Não chama a OpenAI.")
    parser.add_argument("--authorize-paid", required=True)
    parser.add_argument("--authorize-execute", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return run(args.authorize_paid, args.authorize_execute)


if __name__ == "__main__":
    raise SystemExit(main())
