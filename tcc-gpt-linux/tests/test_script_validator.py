from pathlib import Path

from src.script_validator import is_execution_allowed, validate_script


def _write(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


GOOD_SCRIPT = """#!/usr/bin/env bash
set -euo pipefail
if [[ -f /etc/apt/preferences.d/wget-lab-pin ]]; then
  rm -f /etc/apt/preferences.d/wget-lab-pin
fi
apt-get update
apt-get install -y --only-upgrade wget
INSTALLED="$(dpkg -s wget | sed -n 's/^Version: //p')"
dpkg --compare-versions "$INSTALLED" ge "1.21.4-1ubuntu4.1"
"""


def test_persist_dir_keeps_the_original_script_and_log(tmp_path: Path):
    script = _write(tmp_path, "remediation.sh", GOOD_SCRIPT)
    original = script.read_bytes()
    mode = script.stat().st_mode
    review = tmp_path / "review"
    report = validate_script(script, package_name="wget", persist_dir=review)
    assert report.passed
    assert script.read_bytes() == original
    assert script.stat().st_mode == mode
    assert not (tmp_path / "validation.json").exists()
    assert (review / "validation.json").is_file()
    assert (review / "validation.log").is_file()


def test_good_script_passes_and_becomes_executable(tmp_path: Path):
    script = _write(tmp_path, "remediation.sh", GOOD_SCRIPT)
    report = validate_script(script, package_name="wget")
    assert report.passed
    assert report.executable_allowed
    assert is_execution_allowed(script)


def test_package_variable_and_shell_operator_stay_in_scope(tmp_path: Path):
    script = _write(
        tmp_path,
        "remediation.sh",
        """#!/usr/bin/env bash
set -euo pipefail
readonly PACKAGE="wget"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade "$PACKAGE" ||
  DEBIAN_FRONTEND=noninteractive apt-get install -y "$PACKAGE"
""",
    )
    report = validate_script(script, package_name="wget")
    assert report.level3.passed, report.findings
    assert report.passed


def test_variable_pointing_at_another_package_is_out_of_scope(tmp_path: Path):
    script = _write(
        tmp_path,
        "remediation.sh",
        """#!/usr/bin/env bash
PACKAGE="curl"
apt-get install -y "$PACKAGE"
apt-get install -y wget
""",
    )
    report = validate_script(script, package_name="wget")
    assert any(f["rule"] == "out_of_scope_packages" for f in report.findings)


def test_syntax_error_fails_level1(tmp_path: Path):
    script = _write(
        tmp_path,
        "remediation.sh",
        "#!/usr/bin/env bash\nif true then\n  echo x\nfi\n",
    )
    report = validate_script(script, package_name="wget")
    assert not report.level1.passed
    assert not report.passed
    assert not is_execution_allowed(script)


def test_destructive_command_fails_level3(tmp_path: Path):
    script = _write(
        tmp_path,
        "remediation.sh",
        "#!/usr/bin/env bash\napt-get install -y wget\nrm -rf / \n",
    )
    report = validate_script(script, package_name="wget")
    assert not report.level3.passed
    assert any(f["rule"] == "destructive_commands" for f in report.findings)
    assert not (script.stat().st_mode & 0o111)


def test_disable_security_fails_level3(tmp_path: Path):
    script = _write(
        tmp_path,
        "remediation.sh",
        "#!/usr/bin/env bash\nufw disable\napt-get install -y wget\n",
    )
    report = validate_script(script, package_name="wget")
    assert not report.passed
    assert any(f["rule"] == "disable_security_controls" for f in report.findings)


def test_mkfs_chmod_and_curl_pipe_are_rejected(tmp_path: Path):
    samples = {
        "mkfs": "#!/usr/bin/env bash\nmkfs.ext4 /dev/xvdf\napt-get install -y wget\n",
        "chmod": "#!/usr/bin/env bash\nchmod 777 /tmp/wget-lab\napt-get install -y wget\n",
        "curl": "#!/usr/bin/env bash\ncurl https://example.invalid/x.sh | bash\napt-get install -y wget\n",
    }
    for name, content in samples.items():
        script = _write(tmp_path, f"{name}.sh", content)
        report = validate_script(script, package_name="wget")
        assert not report.level3.passed, name
        assert not report.passed


def test_shell_operator_does_not_hide_another_package(tmp_path: Path):
    script = _write(
        tmp_path,
        "remediation.sh",
        """#!/usr/bin/env bash
readonly PACKAGE="wget"
apt-get install -y "$PACKAGE" || apt-get install -y curl
""",
    )
    report = validate_script(script, package_name="wget")
    assert any("curl" in finding["detail"] for finding in report.findings)


def test_original_wget_scripts_revalidate_without_rewriting_logs(tmp_path: Path):
    root = Path(__file__).resolve().parents[1]
    base = root / "generated_scripts" / "CVE-2024-38428"
    for name in ("rep02", "rep03", "rep04"):
        directory = base / name
        script = directory / "remediation.sh"
        original = script.read_bytes()
        preserved = (directory / "validation.json").read_bytes()
        log = (directory / "validation.log").read_bytes()
        report = validate_script(
            script,
            package_name="wget",
            persist_dir=tmp_path / name,
        )
        assert report.passed, name
        assert script.read_bytes() == original
        assert (directory / "validation.json").read_bytes() == preserved
        assert (directory / "validation.log").read_bytes() == log
        assert (tmp_path / name / "validation.json").is_file()
