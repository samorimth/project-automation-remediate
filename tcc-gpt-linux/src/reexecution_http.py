"""Segunda passagem funcional da reexecução.

A sonda file:// devolveu "Unsupported scheme" no wget do Ubuntu 24.04.
Esta passagem repete os três scripts originais, cada um em outra EC2 da mesma AMI,
e testa o wget contra um servidor HTTP em 127.0.0.1. Não chama a OpenAI.
"""

from __future__ import annotations

import hashlib
import json

from .config import LAB_ROOT
from .fresh_instance import InstanceLedger
from .reexecution import (
    CVE_ID,
    EVIDENCE_ROOT,
    EXECUTE_AUTHORIZATION_PHRASE,
    INSPECT_SCRIPT,
    REPETITIONS,
    _clients,
    _initial_ok,
    _parse_lines,
    _script_for,
    _write_json,
    _write_markdown,
    classify_reexecution,
    launch_instance,
    run_shell,
    terminate_instance,
    wait_ssm,
)
from .script_validator import validate_script

HTTP_ROOT = LAB_ROOT / "results" / "reexecution" / f"{CVE_ID}-http"

FUNCTIONAL_HTTP_SCRIPT = r"""#!/usr/bin/env bash
set -u
python3 - << 'PY' &
from http.server import BaseHTTPRequestHandler, HTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"tcc-lab-wget-ok\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, fmt, *args):
        return
HTTPServer(("127.0.0.1", 9876), Handler).serve_forever()
PY
server=$!
sleep 0.4
file_out=$(mktemp)
wget -O "$file_out" --timeout=10 file:///etc/os-release
echo "file_exit=$?"
http_out=$(mktemp)
wget -O "$http_out" --timeout=20 http://127.0.0.1:9876/lab
echo "exit_code=$?"
echo "bytes=$(wc -c < "$http_out" | tr -d ' ')"
echo "first_line=$(head -n 1 "$http_out")"
if command -v oscap >/dev/null 2>&1; then
  echo "scanner=oscap_presente_nao_executado_como_prova"
else
  echo "scanner=indisponivel"
fi
wget --version | head -n 1 || true
kill "$server" >/dev/null 2>&1 || true
wait "$server" 2>/dev/null || true
rm -f "$file_out" "$http_out"
"""


def run_http_followup(authorize_execute: str) -> int:
    if authorize_execute != EXECUTE_AUTHORIZATION_PHRASE:
        raise SystemExit("Execução recusada.")
    prior = json.loads((EVIDENCE_ROOT / "state.json").read_text(encoding="utf-8"))
    outputs = prior["outputs"]
    ami_id = prior["ami_id"]
    ledger = InstanceLedger(expected_ami_id=ami_id, max_simultaneous=1)
    ledger.remember_closed(str(prior.get("baker_instance_id") or ""))
    for row in (prior.get("repetitions") or {}).values():
        ledger.remember_closed(str(row.get("instance_id") or ""))
    ec2, ssm = _clients()
    rows = []
    for repetition in REPETITIONS:
        script_path = _script_for(repetition)
        original = script_path.read_bytes()
        review = validate_script(
            script_path,
            package_name="wget",
            persist_dir=HTTP_ROOT / repetition / "validation-review",
        )
        if script_path.read_bytes() != original:
            raise SystemExit("O script original mudou.")
        instance_id = ""
        destination = HTTP_ROOT / repetition
        record: dict[str, object] = {
            "experiment_id": f"REEXEC-HTTP-{CVE_ID}-{repetition}",
            "set": "reexecucao_http_local",
            "cve_id": CVE_ID,
            "repetition": repetition,
            "script_path": str(script_path.relative_to(LAB_ROOT)),
            "script_sha256": hashlib.sha256(original).hexdigest(),
            "ami_id": ami_id,
            "validation_passed": bool(review.passed),
        }
        execution = None
        before: dict[str, object] = {}
        try:
            instance_id = launch_instance(
                ec2, outputs, ami_id, f"tcc-lab-http-{repetition}", repetition
            )
            record["instance_id"] = instance_id
            ledger.open_instance(instance_id, ami_id, repetition)
            print(f"http {repetition}: {instance_id}", flush=True)
            wait_ssm(ec2, ssm, instance_id)
            before = run_shell(ssm, instance_id, INSPECT_SCRIPT, f"tcc-http-before-{repetition}")
            _write_json(destination / "before.json", before)
            parsed_before = _parse_lines(str(before["stdout"]))
            initial_ok = before["status"] == "Success" and _initial_ok(parsed_before)
            before_http = run_shell(
                ssm,
                instance_id,
                FUNCTIONAL_HTTP_SCRIPT,
                f"tcc-http-before-functional-{repetition}",
            )
            _write_json(destination / "functional-before.json", before_http)
            executed = False
            after_version = None
            functional_ok = None
            if review.passed and initial_ok:
                execution = run_shell(
                    ssm,
                    instance_id,
                    original.decode("utf-8"),
                    f"tcc-http-execute-{repetition}",
                    timeout=900,
                )
                _write_json(destination / "ssm-execute.json", execution)
                executed = True
                after = run_shell(ssm, instance_id, INSPECT_SCRIPT, f"tcc-http-after-{repetition}")
                _write_json(destination / "after.json", after)
                functional = run_shell(
                    ssm,
                    instance_id,
                    FUNCTIONAL_HTTP_SCRIPT,
                    f"tcc-http-after-functional-{repetition}",
                )
                _write_json(destination / "functional.json", functional)
                after_version = _parse_lines(str(after["stdout"])).get("version")
                parsed_functional = _parse_lines(str(functional["stdout"]))
                functional_ok = (
                    functional["status"] == "Success"
                    and parsed_functional.get("exit_code") == "0"
                    and parsed_functional.get("first_line") == "tcc-lab-wget-ok"
                    and int(parsed_functional.get("bytes") or "0") > 0
                )
                record["version_after"] = after_version
                record["functional"] = parsed_functional
                record["functional_before"] = _parse_lines(str(before_http["stdout"]))
                record["execution_status"] = execution["status"]
                record["execution_response_code"] = execution["response_code"]
            else:
                record["execution_status"] = "not_sent"
            kind, reason = classify_reexecution(
                validation_passed=bool(review.passed),
                initial_vulnerable=initial_ok,
                executed=executed,
                version_after=after_version,
                functional_ok=functional_ok,
                fresh_instance=True,
            )
            record["classification"] = kind
            record["classification_reason"] = reason
            record["version_before"] = parsed_before.get("version")
            _write_markdown(destination / "evidence.md", record, before, execution)
            _write_json(destination / "classification.json", record)
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
        rows.append(record)
    _write_json(HTTP_ROOT / "summary.json", {"ami_id": ami_id, "runs": rows})
    print(json.dumps({"ami_id": ami_id, "classifications": [r.get("classification") for r in rows]}))
    return 0
