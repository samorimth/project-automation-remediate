"""Configuração local do laboratório (Fases 1–3).

Os valores sensíveis permanecem fora do Git e fora da instância EC2.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

LAB_ROOT = Path(__file__).resolve().parents[1]
TERRAFORM_DIR = LAB_ROOT / "terraform"
ENV_EXAMPLE = LAB_ROOT / ".env.example"
TFVARS_EXAMPLE = TERRAFORM_DIR / "terraform.tfvars.example"
PROMPTS_DIR = LAB_ROOT / "prompts"
SCENARIOS_DIR = LAB_ROOT / "scenarios"
GENERATED_SCRIPTS_DIR = LAB_ROOT / "generated_scripts"
RESULTS_DIR = LAB_ROOT / "results"

APPLY_AUTHORIZATION_PHRASE = "AUTORIZO_RECURSOS_PAGOS"
DESTROY_AUTHORIZATION_PHRASE = "AUTORIZO_DESTRUIR_RECURSOS"
EXECUTE_AUTHORIZATION_PHRASE = "AUTORIZO_EXECUCAO_SCRIPT_IA"

REQUIRED_ENV_KEYS = (
    "OPENAI_API_KEY",
    "OPENAI_MODEL",
    "OPENAI_TIMEOUT",
    "REPETITIONS",
    "AWS_REGION",
    "MAX_INSTANCES",
)

PAID_RESOURCE_FLAGS = (
    "enable_execution",
    "enable_nat_gateway",
    "enable_ssm_vpc_endpoints",
)

ALLOWED_REGIONS = ("[REDACTED]", "us-east-2", "sa-east-1")  # pragma: allowlist secret

DEFAULT_OPENAI_MODEL = "gpt-4o-mini"
DEFAULT_OPENAI_TIMEOUT = 120
DEFAULT_OPENAI_MAX_RETRIES = 2
DEFAULT_REPETITIONS = 3


class ConfigError(ValueError):
    """A configuração local não pode ser usada."""


@dataclass(frozen=True)
class Settings:
    aws_region: str
    max_instances: int
    instance_count: int
    openai_api_key: str | None
    openai_model: str
    openai_timeout: int
    openai_max_retries: int
    repetitions: int

    def validate_instance_bounds(self) -> None:
        if self.max_instances < 1 or self.max_instances > 3:
            raise ConfigError("max_instances deve estar entre 1 e 3.")
        if self.instance_count < 0:
            raise ConfigError("instance_count não pode ser negativo.")
        if self.instance_count > self.max_instances:
            raise ConfigError(
                "instance_count não pode ser maior que max_instances "
                f"({self.instance_count} > {self.max_instances})."
            )
        if self.aws_region not in ALLOWED_REGIONS:
            raise ConfigError(
                "aws_region deve ser [REDACTED], us-east-2 ou sa-east-1."
            )  # pragma: allowlist secret

    def require_openai(self) -> "Settings":
        if not self.openai_api_key:
            raise ConfigError(
                "OPENAI_API_KEY ausente. Configure o secret no ambiente "
                "antes de gerar scripts."
            )
        if not self.openai_model:
            raise ConfigError("OPENAI_MODEL ausente.")
        if self.openai_timeout < 1:
            raise ConfigError("OPENAI_TIMEOUT deve ser >= 1.")
        return self


def load_settings() -> Settings:
    """Lê o ambiente local. A ausência de .env usa os padrões do laboratório."""
    load_dotenv(LAB_ROOT / ".env")
    region = os.environ.get("AWS_REGION", "us-east-2").strip() or "us-east-2"
    max_instances = _parse_int(os.environ.get("MAX_INSTANCES", "3"), "MAX_INSTANCES")
    instance_count = _parse_int(os.environ.get("INSTANCE_COUNT", "1"), "INSTANCE_COUNT")
    api_key = os.environ.get("OPENAI_API_KEY", "").strip() or None
    model = os.environ.get("OPENAI_MODEL", "").strip() or DEFAULT_OPENAI_MODEL
    timeout = _parse_int(
        os.environ.get("OPENAI_TIMEOUT", str(DEFAULT_OPENAI_TIMEOUT)),
        "OPENAI_TIMEOUT",
    )
    max_retries = _parse_int(
        os.environ.get("OPENAI_MAX_RETRIES", str(DEFAULT_OPENAI_MAX_RETRIES)),
        "OPENAI_MAX_RETRIES",
    )
    repetitions = _parse_int(
        os.environ.get("REPETITIONS", str(DEFAULT_REPETITIONS)),
        "REPETITIONS",
    )
    settings = Settings(
        aws_region=region,
        max_instances=max_instances,
        instance_count=instance_count,
        openai_api_key=api_key,
        openai_model=model,
        openai_timeout=timeout,
        openai_max_retries=max_retries,
        repetitions=repetitions,
    )
    settings.validate_instance_bounds()
    return settings


def parse_tfvars(text: str) -> dict[str, str]:
    """Lê atribuições simples de um arquivo tfvars, sem avaliar expressões."""
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"')
    return values


def load_tfvars(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise ConfigError(f"Arquivo de variáveis não encontrado: {path}")
    return parse_tfvars(path.read_text(encoding="utf-8"))


def assert_safe_example(values: dict[str, str]) -> None:
    """O exemplo versionado precisa manter os recursos pagos desligados."""
    for flag in PAID_RESOURCE_FLAGS:
        if values.get(flag, "false") != "false":
            raise ConfigError(f"{flag} deve permanecer false no exemplo versionado.")
    instance_count = _parse_int(values.get("instance_count", "1"), "instance_count")
    max_instances = _parse_int(values.get("max_instances", "3"), "max_instances")
    Settings(
        aws_region=values.get("aws_region", "us-east-2"),
        max_instances=max_instances,
        instance_count=instance_count,
        openai_api_key=None,
        openai_model=DEFAULT_OPENAI_MODEL,
        openai_timeout=DEFAULT_OPENAI_TIMEOUT,
        openai_max_retries=DEFAULT_OPENAI_MAX_RETRIES,
        repetitions=DEFAULT_REPETITIONS,
    ).validate_instance_bounds()


def _parse_int(raw: str | None, name: str) -> int:
    try:
        return int(str(raw).strip())
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{name} precisa ser um número inteiro.") from exc
