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
