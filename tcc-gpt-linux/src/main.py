"""Interface de linha de comando do laboratório (Fases 1–3)."""

from __future__ import annotations

import argparse
import json
import shutil
import sys

from .aws_manager import AuthorizationError, cleanup, provision
from .config import (
    ENV_EXAMPLE,
    EXECUTE_AUTHORIZATION_PHRASE,
    LAB_ROOT,
    REQUIRED_ENV_KEYS,
    TFVARS_EXAMPLE,
    ConfigError,
    Settings,
    assert_safe_example,
    load_settings,
    load_tfvars,
)
from .experiment_runner import (
    run_execute,
    run_generate,
    run_validate,
    run_verify,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m src.main",
        description=(
            "Laboratório do TCC. check/provision/cleanup (Fase 1); "
            "generate/validate/execute/verify (Fase 3). "
            "Execute de script IA exige autorização explícita."
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

    generate_command = commands.add_parser(
        "generate",
        help="Gera um script Bash de remediação via OpenAI para a CVE indicada.",
    )
    generate_command.add_argument("--cve", required=True)

    validate_command = commands.add_parser(
        "validate",
        help="Valida o último script gerado (bash -n, shellcheck, checklist).",
    )
    validate_command.add_argument("--cve", required=True)
    validate_command.add_argument(
        "--dir",
        default=None,
        help="Pasta repXX específica (padrão: última geração da CVE).",
    )

    execute_command = commands.add_parser(
        "execute",
        help=(
            "Executa o script validado via SSM. "
            f"Exige --authorize {EXECUTE_AUTHORIZATION_PHRASE}."
        ),
    )
    execute_command.add_argument("--cve", required=True)
    execute_command.add_argument("--authorize", default=None)
    execute_command.add_argument("--instance-id", default=None)
    execute_command.add_argument("--dir", default=None)

    verify_command = commands.add_parser(
        "verify",
        help="Verifica independentemente a versão do pacote na EC2 via SSM.",
    )
    verify_command.add_argument("--cve", required=True)
    verify_command.add_argument("--instance-id", default=None)
    verify_command.add_argument("--dir", default=None)

    commands.add_parser(
        "report",
        help="Inativo nesta fase. Reservado para a Fase 6.",
    )
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

    shellcheck_path = shutil.which("shellcheck")
    if shellcheck_path is None:
        print(
            "shellcheck não encontrado no PATH (necessário para validate Nível 2).",
            file=sys.stderr,
        )
        ok = False
    else:
        print(f"shellcheck encontrado em {shellcheck_path}.")

    try:
        example = _read_env_example()
    except ConfigError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    missing = [key for key in REQUIRED_ENV_KEYS if key not in example]
    if missing:
        print(f".env.example sem as chaves: {', '.join(missing)}.", file=sys.stderr)
        ok = False
    elif example.get("OPENAI_API_KEY", None) != "":
        print(".env.example não pode conter valor em OPENAI_API_KEY.", file=sys.stderr)
        ok = False
    else:
        print(".env.example contém as chaves previstas, sem segredo.")

    try:
        example_tfvars = load_tfvars(TFVARS_EXAMPLE)
        assert_safe_example(example_tfvars)
        if (LAB_ROOT / ".env").is_file():
            settings = load_settings()
        else:
            settings = Settings(
                aws_region=example_tfvars.get("aws_region", "us-east-2"),
                max_instances=int(example_tfvars["max_instances"]),
                instance_count=int(example_tfvars["instance_count"]),
                openai_api_key=None,
                openai_model=example.get("OPENAI_MODEL") or "gpt-4o-mini",
                openai_timeout=int(example.get("OPENAI_TIMEOUT") or "120"),
                openai_max_retries=2,
                repetitions=int(example.get("REPETITIONS") or "3"),
            )
            settings.validate_instance_bounds()
        print(
            "Limites do exemplo: "
            f"região {settings.aws_region}, "
            f"instance_count {settings.instance_count}, "
            f"max_instances {settings.max_instances}."
        )
        print("O exemplo do Terraform mantém NAT, endpoints e EC2 desligados.")
        if settings.openai_api_key:
            print("OPENAI_API_KEY presente no ambiente (valor não exibido).")
            print(f"OPENAI_MODEL={settings.openai_model}")
        else:
            print(
                "OPENAI_API_KEY ausente — `generate` bloqueado. "
                "Cadastre a chave em Environment secrets no dashboard "
                "do Cursor (não cole no chat) e reinicie o agente."
            )
    except ConfigError as exc:
        print(str(exc), file=sys.stderr)
        ok = False

    print("Nenhum apply, destroy ou execute de script IA foi realizado.")
    return 0 if ok else 1


def command_generate(cve: str) -> int:
    settings = load_settings()
    result = run_generate(settings, cve)
    print(
        json.dumps(
            {
                "cve": result.cve_id,
                "repetition": result.repetition,
                "model": result.model,
                "latency_ms": result.latency_ms,
                "ok": result.ok,
                "error": result.error,
                "output_dir": result.output_dir,
                "prompt_hash_sha256": result.prompt_hash_sha256,
                "script_hash_sha256": result.script_hash_sha256,
                "total_tokens": result.total_tokens,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0 if result.ok else 1


def command_validate(cve: str, directory: str | None) -> int:
    from pathlib import Path

    gen_dir = Path(directory) if directory else None
    report = run_validate(cve, generation_dir=gen_dir)
    print(
        json.dumps(
            {
                "passed": report.passed,
                "executable_allowed": report.executable_allowed,
                "script_path": report.script_path,
                "findings": report.findings,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0 if report.passed else 1


def command_execute(
    cve: str,
    authorize: str | None,
    instance_id: str | None,
    directory: str | None,
) -> int:
    from pathlib import Path

    settings = load_settings()
    gen_dir = Path(directory) if directory else None
    outcome = run_execute(
        settings,
        cve,
        authorize=authorize,
        instance_id=instance_id,
        generation_dir=gen_dir,
    )
    print(json.dumps(outcome, ensure_ascii=False, indent=2))
    return 0 if outcome.get("remediation_success") else 1


def command_verify(
    cve: str,
    instance_id: str | None,
    directory: str | None,
) -> int:
    from pathlib import Path

    settings = load_settings()
    gen_dir = Path(directory) if directory else None
    outcome = run_verify(
        settings,
        cve,
        instance_id=instance_id,
        generation_dir=gen_dir,
    )
    print(json.dumps(outcome, ensure_ascii=False, indent=2))
    return 0 if outcome.get("ssm_status") == "Success" else 1


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "check":
            return command_check()
        if args.command == "provision":
            return provision(authorize=args.authorize)
        if args.command == "cleanup":
            return cleanup(authorize=args.authorize)
        if args.command == "generate":
            return command_generate(args.cve)
        if args.command == "validate":
            return command_validate(args.cve, args.dir)
        if args.command == "execute":
            return command_execute(
                args.cve, args.authorize, args.instance_id, args.dir
            )
        if args.command == "verify":
            return command_verify(args.cve, args.instance_id, args.dir)
        if args.command == "report":
            print(
                "O comando report pertence à Fase 6 e ainda não está ativo. "
                "Nenhuma figura fictícia foi gerada."
            )
            return 2
        raise ConfigError(f"Comando desconhecido: {args.command}")
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
