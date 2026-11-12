"""Monta o prompt de remediação a partir do template e dos metadados do cenário."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path

from .config import PROMPTS_DIR, SCENARIOS_DIR, ConfigError

DEFAULT_TEMPLATE = PROMPTS_DIR / "remediation_prompt.txt"


@dataclass(frozen=True)
class ScenarioMetadata:
    cve_id: str
    package_name: str
    ubuntu_version: str
    ubuntu_codename: str
    installed_version: str
    fixed_version: str
    description: str
    usn: str | None = None
    instance_id_hint: str | None = None
    aws_region_hint: str | None = None
    approval_status: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return asdict(self)


def scenario_dir(cve_id: str) -> Path:
    return SCENARIOS_DIR / cve_id


def load_scenario(cve_id: str) -> ScenarioMetadata:
    """Carrega scenario.json; se ausente, extrai campos mínimos de scenario.md."""
    directory = scenario_dir(cve_id)
    json_path = directory / "scenario.json"
    if json_path.is_file():
        data = json.loads(json_path.read_text(encoding="utf-8"))
        try:
            return ScenarioMetadata(
                cve_id=data["cve_id"],
                package_name=data["package_name"],
                ubuntu_version=data["ubuntu_version"],
                ubuntu_codename=data["ubuntu_codename"],
                installed_version=data["installed_version"],
                fixed_version=data["fixed_version"],
                description=data["description"],
                usn=data.get("usn"),
                instance_id_hint=data.get("instance_id_hint"),
                aws_region_hint=data.get("aws_region_hint"),
                approval_status=data.get("approval_status"),
            )
        except KeyError as exc:
            raise ConfigError(f"scenario.json incompleto em {json_path}: {exc}") from exc

    md_path = directory / "scenario.md"
    if not md_path.is_file():
        raise ConfigError(f"Cenário não encontrado: {cve_id}")
    return _parse_scenario_markdown(cve_id, md_path.read_text(encoding="utf-8"))


def build_prompt(
    scenario: ScenarioMetadata,
    *,
    template_path: Path | None = None,
) -> str:
    path = template_path or DEFAULT_TEMPLATE
    if not path.is_file():
        raise ConfigError(f"Template de prompt não encontrado: {path}")
    template = path.read_text(encoding="utf-8")
    replacements = {
        "{{CVE_ID}}": scenario.cve_id,
        "{{CVE_DESCRIPTION}}": scenario.description,
        "{{UBUNTU_VERSION}}": scenario.ubuntu_version,
        "{{UBUNTU_CODENAME}}": scenario.ubuntu_codename,
        "{{PACKAGE_NAME}}": scenario.package_name,
        "{{INSTALLED_VERSION}}": scenario.installed_version,
        "{{FIXED_VERSION}}": scenario.fixed_version,
    }
    prompt = template
    for key, value in replacements.items():
        prompt = prompt.replace(key, value)
    leftover = re.findall(r"\{\{[A-Z0-9_]+\}\}", prompt)
    if leftover:
        raise ConfigError(f"Placeholders não preenchidos no prompt: {', '.join(leftover)}")
    return prompt


def _parse_scenario_markdown(cve_id: str, text: str) -> ScenarioMetadata:
    package = _first_match(r"(?im)^- Fonte / binário:\s*`([^`]+)`", text) or "desconhecido"
    ubuntu = _first_match(r"(?im)^Ubuntu\s+([0-9.]+[^\n`]*)", text) or "Ubuntu"
    codename = _first_match(r"`([a-z]+)`", text) or "unknown"
    installed = _first_match(
        r"(?im)`([0-9][^`]+)`\s*\|\s*\*\*versão de preparação",
        text,
    )
    fixed = _first_match(r"(?im)^`([0-9][^`]+)`\s*—\s*publicada", text)
    description = _section_after(text, "## Descrição")
    if not installed or not fixed or not description:
        raise ConfigError(
            f"Não foi possível extrair metadados suficientes de scenario.md para {cve_id}."
        )
    return ScenarioMetadata(
        cve_id=cve_id,
        package_name=package,
        ubuntu_version=ubuntu.strip().rstrip("."),
        ubuntu_codename=codename,
        installed_version=installed,
        fixed_version=fixed,
        description=description.strip(),
    )


def _first_match(pattern: str, text: str) -> str | None:
    match = re.search(pattern, text)
    return match.group(1).strip() if match else None


def _section_after(text: str, heading: str) -> str:
    pattern = re.compile(
        rf"{re.escape(heading)}\s*\n+(.*?)(?=\n## |\Z)",
        re.DOTALL,
    )
    match = pattern.search(text)
    return match.group(1).strip() if match else ""
