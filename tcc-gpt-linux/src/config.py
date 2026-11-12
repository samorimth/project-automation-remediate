"""Configuração local da Fase 1.

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

APPLY_AUTHORIZATION_PHRASE = "AUTORIZO_RECURSOS_PAGOS"
DESTROY_AUTHORIZATION_PHRASE = "AUTORIZO_DESTRUIR_RECURSOS"

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

ALLOWED_REGIONS = ("us-east-1", "us-east-2", "sa-east-1")  # pragma: allowlist secret


class ConfigError(ValueError):
    """A configuração local não pode ser usada."""


@dataclass(frozen=True)
class Settings:
    aws_region: str
    max_instances: int
    instance_count: int

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
            raise ConfigError("aws_region deve ser us-east-1, us-east-2 ou sa-east-1.")  # pragma: allowlist secret


def load_settings() -> Settings:
    """Lê o ambiente local. A ausência de .env usa os padrões da Fase 1."""
    load_dotenv(LAB_ROOT / ".env")
    region = os.environ.get("AWS_REGION", "us-east-2").strip() or "us-east-2"
    max_instances = _parse_int(os.environ.get("MAX_INSTANCES", "3"), "MAX_INSTANCES")
    instance_count = _parse_int(os.environ.get("INSTANCE_COUNT", "1"), "INSTANCE_COUNT")
    settings = Settings(
        aws_region=region,
        max_instances=max_instances,
        instance_count=instance_count,
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
    ).validate_instance_bounds()


def _parse_int(raw: str | None, name: str) -> int:
    try:
        return int(str(raw).strip())
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{name} precisa ser um número inteiro.") from exc
