import hashlib
import json
from pathlib import Path

import pytest

from src.fresh_instance import (
    InstanceLedger,
    MethodologyError,
    ReferenceAmi,
    reexecution_plan,
    reject_restore_baseline,
)
from src.historical_ledger import (
    classify_run,
    estimate_generation_cost_usd,
    experimental_runs,
    infrastructure_attempts,
)

ROOT = Path(__file__).resolve().parents[1]


def test_archived_evidence_still_matches_the_working_tree():
    manifest_path = (
        ROOT / "evidence_archive" / "historical-cve-2024-38428" / "MANIFEST.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["file_count"] == len(manifest["files"])
    mutable_code = "src/script_validator.py"
    for item in manifest["files"]:
        path = ROOT / item["path"]
        copy = manifest_path.parent / "copies" / item["path"]
        assert hashlib.sha256(copy.read_bytes()).hexdigest() == item["sha256"]
        if item["path"] == mutable_code:
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        assert digest == item["sha256"], item["path"]


def test_historical_runs_stay_inconclusive_under_the_new_protocol():
    runs = experimental_runs(ROOT)
    executed = [row for row in runs if row["classification"] != "NAO_EXECUTADO"]
    assert {row["repetition"] for row in executed} == {"2", "3", "4"}
    assert len({row["instance_id"] for row in executed}) == 1
    for row in executed:
        assert row["recorded_remediation_success"] == "1"
        assert row["classification"] == "INCONCLUSIVO"
        assert row["version_before"] == "1.21.4-1ubuntu4"
        assert row["version_after"] == "1.21.4-1ubuntu4.5"
    attempts = infrastructure_attempts(ROOT)
    assert any(row["attempt_id"] == "INF-04" and row["result"] == "falha" for row in attempts)
    assert any(row["attempt_id"] == "INF-05" and row["result"] == "sucesso" for row in attempts)


def test_missing_tokens_have_no_invented_cost():
    assert estimate_generation_cost_usd(None, None) == ""
    assert estimate_generation_cost_usd(585, 548) == "0.000333"


def test_success_requires_a_fresh_instance_and_a_functional_test():
    kind, _reason = classify_run(
        script_exists=True,
        validation_events=[True],
        execution_status="Success",
        version_before="1.21.4-1ubuntu4",
        version_after="1.21.4-1ubuntu4.5",
        fixed_version="1.21.4-1ubuntu4.1",
        functional_test_recorded=True,
        fresh_instance=True,
    )
    assert kind == "SUCESSO"


def test_a_used_instance_cannot_run_another_script():
    ami = ReferenceAmi(
        ami_id="ami-0123456789abcdef0",
        cve_id="CVE-2024-38428",
        ubuntu_release="24.04",
        package_name="wget",
        vulnerable_version="1.21.4-1ubuntu4",
        fixed_version="1.21.4-1ubuntu4.1",
        package_sha256="abc",
        scenario_id="CVE-2024-38428",
    )
    ami.assert_record()
    ledger = InstanceLedger(expected_ami_id=ami.ami_id, max_simultaneous=1)
    ledger.open_instance("i-aaaaaaaaaaaaaaaaa", ami.ami_id, "rep02")
    with pytest.raises(MethodologyError):
        ledger.open_instance("i-aaaaaaaaaaaaaaaaa", ami.ami_id, "rep03")
    with pytest.raises(MethodologyError):
        ledger.open_instance("i-bbbbbbbbbbbbbbbbb", ami.ami_id, "rep03")
    ledger.close_instance("i-aaaaaaaaaaaaaaaaa")
    with pytest.raises(MethodologyError):
        ledger.open_instance("i-aaaaaaaaaaaaaaaaa", ami.ami_id, "rep03")
    ledger.open_instance("i-bbbbbbbbbbbbbbbbb", ami.ami_id, "rep03")
    with pytest.raises(MethodologyError):
        reject_restore_baseline("prepare.sh --apply")
    assert "OpenAI" in " ".join(reexecution_plan())
