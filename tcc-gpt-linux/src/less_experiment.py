"""Experimento da CVE-2024-32487 (less) em EC2 nova por script.

Três gerações usam o mesmo prompt e os mesmos parâmetros. Cada script aprovado
roda uma vez, numa instância criada da AMI privada, e essa instância é destruída
depois da coleta. Este módulo não altera experiments.json nem os scripts do wget.
"""

from __future__ import annotations

import argparse
import atexit
import hashlib
import json
import signal
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from .aws_manager import AuthorizationError, destroy_infrastructure
from .config import (
    APPLY_AUTHORIZATION_PHRASE,
    DESTROY_AUTHORIZATION_PHRASE,
    EXECUTE_AUTHORIZATION_PHRASE,
    GENERATED_SCRIPTS_DIR,
    LAB_ROOT,
    load_settings,
)
from .fresh_instance import InstanceLedger, ReferenceAmi, reject_restore_baseline
from .historical_ledger import estimate_generation_cost_usd
from .openai_client import OpenAIClient
from .prompt_builder import build_prompt, load_scenario
from .reexecution import (
    HARDEN_SCRIPT,
    INSTANCE_TYPE,
    PUBLIC_BASE_AMI,
    REGION,
    _ami_is_private,
    _parse_lines,
    _utc_now,
    _write_json,
    launch_instance,
    run_shell,
    terminate_instance,
    terraform_apply,
    wait_ssm,
)
from .script_validator import validate_script

CVE_ID = "CVE-2024-32487"
PACKAGE = "less"
VULNERABLE_VERSION = "590-2ubuntu2"
FIXED_VERSION = "590-2ubuntu2.1"
PACKAGE_SHA256 = "e8560662fbf944dd4a4348faa0d8b4652fbc24939e6fe4ac06c0bdf946f9f935"
UBUNTU_CODENAME = "noble"
UBUNTU_VERSION_ID = "24.04"
EXPERIMENT_ID = "cve-2024-32487"
WGET_AMI_ID = "ami-03629c5c47c71759b"
WGET_SNAPSHOT_ID = "snap-00f4c9aff7066895b"
WGET_VPC_ID = "vpc-07ed5b7db90bfd3a6"
EVIDENCE_ROOT = LAB_ROOT / "results" / "reexecution" / CVE_ID
STATE_PATH = EVIDENCE_ROOT / "state.json"
SCRIPTS_ROOT = GENERATED_SCRIPTS_DIR / CVE_ID
PREPARE_SCRIPT = LAB_ROOT / "scenarios" / CVE_ID / "prepare.sh"
TFSTATE = LAB_ROOT / "terraform" / "terraform.tfstate"
GENERATION_COUNT = 3

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
unset LESSOPEN
unset LESSCLOSE
src=$(mktemp)
out=$(mktemp)
printf 'tcc-lab-less-ok\\n' > "$src"
TERM=dumb less -F -E -X "$src" > "$out"
code=$?
echo "exit_code=$code"
echo "bytes=$(wc -c < "$out" | tr -d ' ')"
if grep -q 'tcc-lab-less-ok' "$out"; then
  echo "first_line=tcc-lab-less-ok"
else
  echo "first_line=$(head -n 1 "$out" | tr -cd '[:alnum:]-')"
fi
rm -f "$src" "$out"
less --version | head -n 1 || true
if command -v oscap >/dev/null 2>&1; then
  echo "scanner=oscap_presente_nao_executado_como_prova"
else
  echo "scanner=indisponivel"
fi
"""


def classify_less(
    *,
    validation_passed: bool,
    initial_vulnerable: bool,
    functional_before_ok: bool,
    executed: bool,
    version_after: str | None,
    functional_ok: bool | None,
    fresh_instance: bool,
) -> tuple[str, str]:
    if not validation_passed:
        return "BLOQUEADO", "O validador recusou o script. Nenhum comando foi enviado."
    if not initial_vulnerable:
        return (
            "INCONCLUSIVO",
            "O estado inicial não era less 590-2ubuntu2 no Ubuntu 24.04. O script não foi executado.",
        )
    if not functional_before_ok:
        return (
            "INCONCLUSIVO",
            "O teste funcional do less falhou antes da remediação. O script não foi executado.",
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
            "Estado inicial vulnerável, versão posterior atende 590-2ubuntu2.1 e o less leu o arquivo local.",
        )
    if not functional_ok:
        return "FALHA", "O teste funcional do less não teve êxito depois da execução."
    return "FALHA", "A versão posterior permanece abaixo de 590-2ubuntu2.1."


def _version_at_least(installed: str, minimum: str) -> bool:
    import subprocess

    completed = subprocess.run(
        ["dpkg", "--compare-versions", installed, "ge", minimum],
        check=False,
        capture_output=True,
    )
    if completed.returncode == 0:
        return True
    if completed.returncode == 1:
        return False
    raise RuntimeError("dpkg --compare-versions indisponível.")


def _load_state() -> dict[str, Any]:
    if not STATE_PATH.is_file():
        return {"repetitions": {}, "generations": []}
    return json.loads(STATE_PATH.read_text(encoding="utf-8"))


def _save_state(state: dict[str, Any]) -> None:
    state["updated_at_utc"] = _utc_now()
    _write_json(STATE_PATH, state)


def _clients() -> tuple[Any, Any]:
    return boto3.client("ec2", region_name=REGION), boto3.client("ssm", region_name=REGION)


def _initial_ok(parsed: dict[str, str]) -> bool:
    return (
        parsed.get("id") == "ubuntu"
        and parsed.get("version_id") == UBUNTU_VERSION_ID
        and parsed.get("codename") == UBUNTU_CODENAME
        and parsed.get("version") == VULNERABLE_VERSION
        and parsed.get("compare") == "lt"
    )


def _functional_ok(payload: dict[str, Any]) -> bool:
    parsed = _parse_lines(payload.get("stdout") or "")
    return (
        payload.get("status") == "Success"
        and parsed.get("exit_code") == "0"
        and parsed.get("first_line") == "tcc-lab-less-ok"
        and int(parsed.get("bytes") or "0") > 0
    )


def _managed_vpc_id() -> str:
    if not TFSTATE.is_file():
        return ""
    state = json.loads(TFSTATE.read_text(encoding="utf-8"))
    for resource in state.get("resources") or []:
        if resource.get("type") == "aws_vpc" and resource.get("name") == "lab":
            for instance in resource.get("instances") or []:
                return str((instance.get("attributes") or {}).get("id") or "")
    return ""


def destroy_previous_wget_stack(ec2: Any, authorize_destroy: str) -> dict[str, Any]:
    """Desliga a pilha e a AMI do wget. Não toca em recursos sem essa etiqueta."""
    if authorize_destroy != DESTROY_AUTHORIZATION_PHRASE:
        raise AuthorizationError("Destruição recusada.")
    report: dict[str, Any] = {"timestamp_utc": _utc_now(), "ami": "", "snapshot": "", "terraform": ""}
    try:
        images = ec2.describe_images(ImageIds=[WGET_AMI_ID]).get("Images") or []
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        images = []
        report["ami"] = code
    for image in images:
        if image.get("Public") or not str(image.get("Name") or "").startswith("tcc-lab-wget"):
            raise RuntimeError("A AMI informada não é a referência privada do wget.")
        ec2.deregister_image(ImageId=WGET_AMI_ID)
        report["ami"] = "deregistered"
    if not report["ami"]:
        report["ami"] = "already_absent"
    try:
        snaps = ec2.describe_snapshots(SnapshotIds=[WGET_SNAPSHOT_ID]).get("Snapshots") or []
    except ClientError as exc:
        snaps = []
        report["snapshot"] = exc.response.get("Error", {}).get("Code", "")
    for snap in snaps:
        if snap.get("SnapshotId") != WGET_SNAPSHOT_ID:
            continue
        ec2.delete_snapshot(SnapshotId=WGET_SNAPSHOT_ID)
        report["snapshot"] = "deleted"
    if not report["snapshot"]:
        report["snapshot"] = "already_absent"
    vpc_id = _managed_vpc_id()
    if vpc_id == WGET_VPC_ID:
        code = destroy_infrastructure(authorize=authorize_destroy)
        report["terraform"] = f"destroy_exit_{code}"
        if code != 0:
            raise RuntimeError("terraform destroy da pilha do wget falhou.")
    elif vpc_id:
        report["terraform"] = f"state_vpc_{vpc_id}_nao_e_a_do_wget"
    else:
        report["terraform"] = "state_sem_vpc"
    return report


def _scrub_secrets(directory: Path) -> None:
    import re

    if not directory.is_dir():
        return
    pattern = re.compile(r"sk-[A-Za-z0-9_\-]+")
    for item in directory.rglob("*"):
        if not item.is_file() or item.suffix not in {".json", ".txt", ".log", ".md"}:
            continue
        text = item.read_text(encoding="utf-8", errors="replace")
        if "sk-" in text:
            item.write_text(pattern.sub("[redacted]", text), encoding="utf-8")


def _stamp_allowlist(path: Path, model: str) -> None:
    if len(model) != 10 or not model.startswith("gpt-"):
        return
    lines = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if model in line and "allowlist secret" not in line and line.rstrip().endswith(","):
            line = line.rstrip()[:-1] + ', "_allowlist": "// pragma: allowlist secret",'
        lines.append(line)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def generate_scripts(state: dict[str, Any]) -> list[dict[str, Any]]:
    """Três chamadas, o mesmo prompt. Não grava em experiments.json."""
    existing = list(state.get("generations") or [])
    if len(existing) >= GENERATION_COUNT:
        return existing
    settings = load_settings().require_openai()
    scenario = load_scenario(CVE_ID)
    prompt = build_prompt(scenario)
    client = OpenAIClient(settings)
    while len(existing) < GENERATION_COUNT:
        result = client.generate_remediation_script(cve_id=CVE_ID, prompt=prompt)
        meta = Path(result.metadata_path or "")
        if meta.is_file():
            _stamp_allowlist(meta, result.model or "")
        if result.output_dir:
            _scrub_secrets(Path(result.output_dir))
        row = {
            "repetition": result.repetition,
            "output_dir": result.output_dir,
            "model": result.model,
            "latency_ms": result.latency_ms,
            "prompt_tokens": result.prompt_tokens,
            "completion_tokens": result.completion_tokens,
            "total_tokens": result.total_tokens,
            "reasoning_effort": result.reasoning_effort,
            "reasoning_tokens": result.reasoning_tokens,
            "script_sha256": result.script_hash_sha256,
            "error": result.error,
            "ok": result.ok,
            "estimated_cost_usd": estimate_generation_cost_usd(
                result.prompt_tokens, result.completion_tokens
            ),
            "timestamp_utc": result.timestamp_utc,
        }
        existing.append(row)
        state["generations"] = existing
        _save_state(state)
        _write_json(EVIDENCE_ROOT / "generations.json", {"calls": existing, "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest()})
        if result.error and ("429" in result.error or "insufficient_quota" in result.error):
            break
    return existing


def bake_ami(ec2: Any, ssm: Any, outputs: dict[str, Any], state: dict[str, Any]) -> str:
    if state.get("ami_id"):
        ami_id = str(state["ami_id"])
        ec2.get_waiter("image_available").wait(ImageIds=[ami_id], WaiterConfig={"Delay": 20, "MaxAttempts": 90})
        if not state.get("baker_terminated") and state.get("baker_instance_id"):
            cleanup = terminate_instance(ec2, str(state["baker_instance_id"]))
            state["baker_terminated"] = True
            _save_state(state)
            _write_json(EVIDENCE_ROOT / "ami" / "baker-cleanup.json", cleanup)
        return ami_id
    instance_id = launch_instance(
        ec2,
        outputs,
        PUBLIC_BASE_AMI,
        "tcc-lab-less-baker",
        "baker",
        experiment_id=EXPERIMENT_ID,
    )
    state["baker_instance_id"] = instance_id
    _save_state(state)
    wait_ssm(ec2, ssm, instance_id)
    hardened = run_shell(ssm, instance_id, HARDEN_SCRIPT, "tcc-less-harden-baker")
    _write_json(EVIDENCE_ROOT / "ami" / "harden.json", hardened)
    prepared = run_shell(
        ssm,
        instance_id,
        PREPARE_SCRIPT.read_text(encoding="utf-8"),
        "tcc-less-prepare-baker",
        timeout=900,
        args="--apply",
    )
    _write_json(EVIDENCE_ROOT / "ami" / "prepare.json", prepared)
    if prepared["status"] != "Success":
        raise RuntimeError("prepare.sh --apply do less falhou. Nenhum script de remediação foi executado.")
    inspected = run_shell(ssm, instance_id, INSPECT_SCRIPT, "tcc-less-inspect-baker")
    _write_json(EVIDENCE_ROOT / "ami" / "before-image.json", inspected)
    parsed = _parse_lines(inspected["stdout"])
    if not _initial_ok(parsed):
        raise RuntimeError(f"A instância auxiliar não ficou no estado vulnerável esperado: {parsed}")
    functional = run_shell(ssm, instance_id, FUNCTIONAL_SCRIPT, "tcc-less-functional-baker")
    _write_json(EVIDENCE_ROOT / "ami" / "functional-before-image.json", functional)
    if not _functional_ok(functional):
        raise RuntimeError("O teste funcional do less falhou na instância auxiliar. A AMI não foi criada.")
    image = ec2.create_image(
        InstanceId=instance_id,
        Name=f"tcc-lab-less-{VULNERABLE_VERSION}-{_utc_now().replace(':', '').replace('-', '')}",
        Description=f"{CVE_ID} Ubuntu {UBUNTU_VERSION_ID} {PACKAGE} {VULNERABLE_VERSION} minima {FIXED_VERSION}",
        NoReboot=False,
        TagSpecifications=[
            {
                "ResourceType": "image",
                "Tags": [
                    {"Key": "Name", "Value": "tcc-lab-reference-cve-2024-32487"},
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
    ec2.get_waiter("image_available").wait(ImageIds=[ami_id], WaiterConfig={"Delay": 20, "MaxAttempts": 90})
    private = _ami_is_private(ec2, ami_id)
    described = ec2.describe_images(ImageIds=[ami_id])["Images"][0]
    record = {
        "ami_id": ami_id,
        "private": private,
        "public": described.get("Public"),
        "name": described.get("Name"),
        "creation_date": described.get("CreationDate"),
        "ubuntu_release": UBUNTU_VERSION_ID,
        "codename": UBUNTU_CODENAME,
        "package": PACKAGE,
        "vulnerable_version": VULNERABLE_VERSION,
        "fixed_version": FIXED_VERSION,
        "package_sha256": PACKAGE_SHA256,
        "cve": CVE_ID,
        "source_public_ami": PUBLIC_BASE_AMI,
        "baker_instance_id": instance_id,
        "inspect": parsed,
        "created_at_utc": _utc_now(),
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
    state["baker_terminated"] = True
    state["reference"] = record
    _save_state(state)
    _write_json(EVIDENCE_ROOT / "ami" / "baker-cleanup.json", cleanup)
    return ami_id


def _script_for(repetition: int) -> Path:
    path = SCRIPTS_ROOT / f"rep{repetition:02d}" / "remediation.sh"
    if not path.is_file():
        raise FileNotFoundError(path)
    return path


def run_repetition(
    ec2: Any,
    ssm: Any,
    outputs: dict[str, Any],
    ami_id: str,
    repetition: int,
    ledger: InstanceLedger,
    authorize_execute: str,
) -> dict[str, Any]:
    if authorize_execute != EXECUTE_AUTHORIZATION_PHRASE:
        raise AuthorizationError("Execução recusada.")
    reject_restore_baseline("ami de referência")
    label = f"rep{repetition:02d}"
    script_path = _script_for(repetition)
    original = script_path.read_bytes()
    review = validate_script(script_path, package_name=PACKAGE)
    if script_path.read_bytes() != original:
        raise AuthorizationError("O script gerado mudou de bytes durante a validação.")
    destination = EVIDENCE_ROOT / label
    record: dict[str, Any] = {
        "experiment_id": f"{CVE_ID}-{label}",
        "set": "cve-2024-32487",
        "cve_id": CVE_ID,
        "repetition": label,
        "script_sha256": hashlib.sha256(original).hexdigest(),
        "ami_id": ami_id,
        "instance_id": "",
        "validation_passed": bool(review.passed),
    }
    instance_id = ""
    try:
        if not review.passed:
            classification, reason = classify_less(
                validation_passed=False,
                initial_vulnerable=False,
                functional_before_ok=False,
                executed=False,
                version_after=None,
                functional_ok=None,
                fresh_instance=False,
            )
            record["classification"] = classification
            record["classification_reason"] = reason
            _write_json(destination / "classification.json", record)
            return record
        instance_id = launch_instance(
            ec2,
            outputs,
            ami_id,
            f"tcc-lab-less-{label}",
            label,
            experiment_id=EXPERIMENT_ID,
        )
        record["instance_id"] = instance_id
        ledger.open_instance(instance_id, ami_id, label)
        wait_ssm(ec2, ssm, instance_id)
        before = run_shell(ssm, instance_id, INSPECT_SCRIPT, f"tcc-less-before-{label}")
        _write_json(destination / "before.json", before)
        parsed_before = _parse_lines(before["stdout"])
        functional_before = run_shell(ssm, instance_id, FUNCTIONAL_SCRIPT, f"tcc-less-functional-before-{label}")
        _write_json(destination / "functional-before.json", functional_before)
        initial_ok = before["status"] == "Success" and _initial_ok(parsed_before)
        before_ok = _functional_ok(functional_before)
        executed = False
        execution = None
        after_version = None
        functional_ok = None
        record["version_before"] = parsed_before.get("version")
        if initial_ok and before_ok:
            execution = run_shell(
                ssm,
                instance_id,
                original.decode("utf-8"),
                f"tcc-less-execute-{label}",
                timeout=900,
            )
            _write_json(destination / "ssm-execute.json", execution)
            executed = True
            after = run_shell(ssm, instance_id, INSPECT_SCRIPT, f"tcc-less-after-{label}")
            _write_json(destination / "after.json", after)
            functional = run_shell(ssm, instance_id, FUNCTIONAL_SCRIPT, f"tcc-less-functional-{label}")
            _write_json(destination / "functional.json", functional)
            after_version = _parse_lines(after["stdout"]).get("version")
            functional_ok = _functional_ok(functional)
            record["version_after"] = after_version
            record["execution_status"] = execution["status"]
            record["execution_response_code"] = execution["response_code"]
            record["ssm_command_id"] = execution["command_id"]
        classification, reason = classify_less(
            validation_passed=True,
            initial_vulnerable=initial_ok,
            functional_before_ok=before_ok,
            executed=executed,
            version_after=after_version,
            functional_ok=functional_ok,
            fresh_instance=True,
        )
        record["classification"] = classification
        record["classification_reason"] = reason
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
            _write_json(destination / "classification.json", record)


def _terminate_open_instances() -> None:
    try:
        ec2 = boto3.client("ec2", region_name=REGION)
        response = ec2.describe_instances(
            Filters=[
                {"Name": "tag:ExperimentId", "Values": [EXPERIMENT_ID]},
                {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]},
            ]
        )
        ids = [
            item["InstanceId"]
            for reservation in response["Reservations"]
            for item in reservation["Instances"]
        ]
        if ids:
            ec2.terminate_instances(InstanceIds=ids)
    except (ClientError, BotoCoreError) as exc:
        print(f"Não foi possível encerrar instâncias do less: {exc}", flush=True)


def _delete_snapshot(ec2: Any, snapshot_id: str) -> None:
    import time

    last_error: Exception | None = None
    for _ in range(12):
        try:
            ec2.delete_snapshot(SnapshotId=snapshot_id)
            return
        except ClientError as exc:
            last_error = exc
            time.sleep(10)
    if last_error:
        raise last_error


def destroy_less_shared(ec2: Any, authorize_destroy: str, state: dict[str, Any]) -> dict[str, Any]:
    if authorize_destroy != DESTROY_AUTHORIZATION_PHRASE:
        raise AuthorizationError("Destruição recusada.")
    report: dict[str, Any] = {"timestamp_utc": _utc_now()}
    ami_id = str(state.get("ami_id") or "")
    if ami_id:
        images = ec2.describe_images(ImageIds=[ami_id]).get("Images") or []
        for image in images:
            if image.get("Public") or not str(image.get("Name") or "").startswith("tcc-lab-less"):
                raise RuntimeError("Recusa ao remover uma AMI que não é a do less.")
            snaps = [
                device.get("Ebs", {}).get("SnapshotId")
                for device in image.get("BlockDeviceMappings") or []
                if device.get("Ebs", {}).get("SnapshotId")
            ]
            report["snapshot_ids"] = snaps
            ec2.deregister_image(ImageId=ami_id)
            for snap in snaps:
                _delete_snapshot(ec2, snap)
            report["ami"] = "deregistered"
    vpc_id = _managed_vpc_id()
    if vpc_id and vpc_id != WGET_VPC_ID:
        code = destroy_infrastructure(authorize=authorize_destroy)
        report["terraform"] = f"destroy_exit_{code}"
        report["vpc_id"] = vpc_id
        if code != 0:
            raise RuntimeError("terraform destroy da pilha do less falhou.")
    else:
        report["terraform"] = "state_sem_pilha_do_less"
    return report


def run(authorize_paid: str, authorize_execute: str, authorize_destroy: str) -> int:
    if authorize_paid != APPLY_AUTHORIZATION_PHRASE:
        raise AuthorizationError("Apply recusado.")
    if authorize_execute != EXECUTE_AUTHORIZATION_PHRASE:
        raise AuthorizationError("Execução recusada.")
    if authorize_destroy != DESTROY_AUTHORIZATION_PHRASE:
        raise AuthorizationError("Destruição recusada.")
    atexit.register(_terminate_open_instances)
    def _stop(signum: int, _frame: object) -> None:
        print(f"Sinal {signum}: encerrando instâncias do less.", flush=True)
        _terminate_open_instances()
        raise SystemExit(1)

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    EVIDENCE_ROOT.mkdir(parents=True, exist_ok=True)
    state = _load_state()
    generations = generate_scripts(state)
    produced = [row for row in generations if row.get("ok")]
    if len(produced) < GENERATION_COUNT:
        if not state.get("previous_wget_destroyed"):
            ec2, _ssm = _clients()
            cleanup = destroy_previous_wget_stack(ec2, authorize_destroy)
            state["previous_wget_destroyed"] = True
            state["wget_cleanup"] = cleanup
            _save_state(state)
        _write_json(EVIDENCE_ROOT / "generations.json", {"calls": generations, "stopped_before_aws": True})
        print(json.dumps({"generated": len(produced), "calls": len(generations)}, ensure_ascii=False))
        return 2
    ec2, ssm = _clients()
    if not state.get("previous_wget_destroyed"):
        cleanup = destroy_previous_wget_stack(ec2, authorize_destroy)
        state["previous_wget_destroyed"] = True
        state["wget_cleanup"] = cleanup
        _save_state(state)
        _write_json(EVIDENCE_ROOT / "wget-cleanup.json", cleanup)
    outputs = terraform_apply(experiment_id=EXPERIMENT_ID)
    state["outputs"] = {
        "vpc_id": outputs.get("vpc_id"),
        "private_subnet_id": outputs.get("private_subnet_id"),
        "nat_gateway_id": outputs.get("nat_gateway_id") if "nat_gateway_id" in outputs else None,
        "lab_security_group_id": outputs.get("lab_security_group_id"),
        "instance_profile_name": outputs.get("instance_profile_name"),
    }
    _save_state(state)
    ami_id = bake_ami(ec2, ssm, outputs, state)
    ledger = InstanceLedger(expected_ami_id=ami_id, max_simultaneous=1)
    ledger.remember_closed(str(state.get("baker_instance_id") or ""))
    rows = []
    for row in generations:
        if not row.get("ok"):
            continue
        repetition = int(row["repetition"])
        label = f"rep{repetition:02d}"
        previous = (state.get("repetitions") or {}).get(label)
        if previous and previous.get("cleanup", {}).get("terminated") and previous.get("classification"):
            rows.append(previous)
            ledger.remember_closed(str(previous.get("instance_id") or ""))
            continue
        result = run_repetition(ec2, ssm, outputs, ami_id, repetition, ledger, authorize_execute)
        state.setdefault("repetitions", {})[label] = result
        _save_state(state)
        rows.append(result)
    shared = destroy_less_shared(ec2, authorize_destroy, state)
    state["shared_cleanup"] = shared
    _save_state(state)
    _write_json(EVIDENCE_ROOT / "shared-cleanup.json", shared)
    _write_json(EVIDENCE_ROOT / "summary.json", {"ami_id": ami_id, "generations": generations, "runs": rows, "shared_cleanup": shared})
    print(json.dumps({"ami_id": ami_id, "runs": [row.get("classification") for row in rows]}, ensure_ascii=False))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Experimento do less. Exige as três frases.")
    parser.add_argument("--authorize-paid", required=True)
    parser.add_argument("--authorize-execute", required=True)
    parser.add_argument("--authorize-destroy", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return run(args.authorize_paid, args.authorize_execute, args.authorize_destroy)


if __name__ == "__main__":
    raise SystemExit(main())
