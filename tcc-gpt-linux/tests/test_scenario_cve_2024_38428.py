"""Metadados e scripts da CVE-2024-38428 (aprovada) — sem AWS e sem GPT."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCENARIO_DIR = ROOT / "scenarios" / "CVE-2024-38428"
SCENARIOS_README = ROOT / "scenarios" / "README.md"
SCRIPTS = ("prepare.sh", "verify_before.sh", "verify_after.sh")

VULN_VERSION = "1.21.4-1ubuntu4"
FIXED_VERSION = "1.21.4-1ubuntu4.1"
DEB_SHA256 = "1d078bf2a22c2c6da84788818ebf055a10f5f6b5ea629f1dd0dd11660b51def6"
ARCHIVE_URL = (
    "https://archive.ubuntu.com/ubuntu/pool/main/w/wget/"
    f"wget_{VULN_VERSION}_amd64.deb"
)


def test_scenario_markdown_exists_with_official_versions():
    path = SCENARIO_DIR / "scenario.md"
    text = path.read_text(encoding="utf-8")
    assert "CVE-2024-38428" in text
    assert "**aprovada**" in text
    assert VULN_VERSION in text
    assert FIXED_VERSION in text
    assert "USN-6852-1" in text
    assert "https://ubuntu.com/security/CVE-2024-38428" in text
    assert ARCHIVE_URL in text
    assert DEB_SHA256 in text
    assert "AUTORIZO_RECURSOS_PAGOS" in text


def test_scenarios_readme_marks_cve_as_approved():
    text = SCENARIOS_README.read_text(encoding="utf-8")
    assert "CVE-2024-38428" in text
    assert "aprovada" in text.lower()
    assert "AUTORIZO_RECURSOS_PAGOS" in text
    assert "enable_nat_gateway" in text
    assert "enable_execution" in text


def test_preparation_scripts_exist_and_are_safe_drafts():
    for name in SCRIPTS:
        path = SCENARIO_DIR / name
        assert path.is_file(), name
        text = path.read_text(encoding="utf-8")
        assert "set -euo pipefail" in text
        assert "noble" in text
        assert FIXED_VERSION in text
        assert "não abre portas" in text.lower() or "recusa abrir portas" in text.lower() or "NÃO abre portas" in text


def test_prepare_script_pins_official_artifact():
    text = (SCENARIO_DIR / "prepare.sh").read_text(encoding="utf-8")
    assert VULN_VERSION in text
    assert ARCHIVE_URL in text or f"wget_${{VULN_VERSION}}_amd64.deb" in text
    assert DEB_SHA256 in text
    assert "--check" in text
    assert "--dry-run" in text
    assert "archive.ubuntu.com" in text
    assert "launchpad.net" in text


def test_bash_syntax_of_scenario_scripts():
    for name in SCRIPTS:
        path = SCENARIO_DIR / name
        completed = subprocess.run(
            ["bash", "-n", str(path)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert completed.returncode == 0, f"{name}: {completed.stderr}"


def test_shellcheck_of_scenario_scripts_if_available():
    if shutil.which("shellcheck") is None:
        return
    for name in SCRIPTS:
        path = SCENARIO_DIR / name
        completed = subprocess.run(
            ["shellcheck", "-x", str(path)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert completed.returncode == 0, f"{name}:\n{completed.stdout}\n{completed.stderr}"
