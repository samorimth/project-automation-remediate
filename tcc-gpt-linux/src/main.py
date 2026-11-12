"""Interface de linha de comando da Fase 1 do laboratório."""

from __future__ import annotations

import argparse
import shutil
import sys

from .aws_manager import AuthorizationError, cleanup, provision
from .config import (
    ENV_EXAMPLE,
    LAB_ROOT,
    REQUIRED_ENV_KEYS,
    TFVARS_EXAMPLE,
    ConfigError,
    Settings,
    assert_safe_example,
    load_settings,
    load_tfvars,
)

DEFERRED_PHASE = {
    "generate": "Fase 3",
    "validate": "Fase 3",
    "execute": "Fase 3",
    "verify": "Fase 2",
    "report": "Fase 6",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m src.main",
        description=(
            "Laboratório do TCC. Na Fase 1, check, provision e cleanup "
            "preparam a infraestrutura. O apply e o destroy exigem autorização."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("check", help="Verifica o ambiente local, sem acessar a AWS.")

    provision_command = commands.add_parser(
        "provision",
        help="Executa init, validate e plan. Não executa apply sem autorização.",
    )
    provision_command.add_argument("--authorize", default=None)

    cleanup_command = commands.add_parser(
        "cleanup",
        help="Prepara o destroy. Não destrói recursos sem autorização.",
    )
    cleanup_command.add_argument("--authorize", default=None)

    for name in DEFERRED_PHASE:
        command = commands.add_parser(
            name,
            help=f"Inativo nesta fase. Reservado para a {DEFERRED_PHASE[name]}.",
        )
        if name in {"generate", "execute", "verify"}:
            command.add_argument("--cve", default=None)
    return parser


def command_check() -> int:
    """Confere dependências e os arquivos de exemplo. Não chama a AWS."""
    ok = True

    if sys.version_info < (3, 11):
        print("Python 3.11 ou superior é obrigatório.", file=sys.stderr)
        ok = False
    else:
        print(f"Python {sys.version.split()[0]} encontrado.")

    terraform_path = shutil.which("terraform")
    if terraform_path is None:
        print("Terraform não encontrado no PATH.", file=sys.stderr)
        ok = False
    else:
        print(f"Terraform encontrado em {terraform_path}.")

    aws_path = shutil.which("aws")
    if aws_path is None:
        print("AWS CLI não encontrada. Ela não é necessária para o validate local.")
    else:
        print(f"AWS CLI encontrada em {aws_path}.")

    try:
        example = _read_env_example()
        missing = [key for key in REQUIRED_ENV_KEYS if key not in example]
        if missing:
            print(f".env.example sem as chaves: {', '.join(missing)}.", file=sys.stderr)
            ok = False
        elif example.get("OPENAI_API_KEY", None) != "":
            print(".env.example não pode conter valor em OPENAI_API_KEY.", file=sys.stderr)
            ok = False
        else:
            print(".env.example contém as chaves previstas, sem segredo.")

        example_tfvars = load_tfvars(TFVARS_EXAMPLE)
        assert_safe_example(example_tfvars)
        if (LAB_ROOT / ".env").is_file():
            settings = load_settings()
        else:
            settings = Settings(
                aws_region=example_tfvars.get("aws_region", "us-east-2"),
                max_instances=int(example_tfvars["max_instances"]),
                instance_count=int(example_tfvars["instance_count"]),
            )
            settings.validate_instance_bounds()
        print(
            "Limites do exemplo: "
            f"região {settings.aws_region}, "
            f"instance_count {settings.instance_count}, "
            f"max_instances {settings.max_instances}."
        )
        print("O exemplo do Terraform mantém NAT, endpoints e EC2 desligados.")
    except ConfigError as exc:
        print(str(exc), file=sys.stderr)
        ok = False

    print("Nenhum apply ou destroy foi executado.")
    return 0 if ok else 1


def command_deferred(command: str) -> int:
    phase = DEFERRED_PHASE[command]
    print(
        f"O comando {command} pertence à {phase} e ainda não está ativo. "
        "Nenhuma chamada de API, nenhum script e nenhum recurso AWS foram produzidos."
    )
    return 2


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "check":
            return command_check()
        if args.command == "provision":
            return provision(authorize=args.authorize)
        if args.command == "cleanup":
            return cleanup(authorize=args.authorize)
        return command_deferred(args.command)
    except (AuthorizationError, ConfigError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


def _read_env_example() -> dict[str, str]:
    if not ENV_EXAMPLE.is_file():
        raise ConfigError(".env.example não encontrado.")
    values: dict[str, str] = {}
    for raw_line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


if __name__ == "__main__":
    sys.exit(main())
