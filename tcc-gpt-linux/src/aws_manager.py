"""Prepara Terraform sem criar ou destruir recursos sem autorização."""

from __future__ import annotations

import subprocess

from .config import (
    APPLY_AUTHORIZATION_PHRASE,
    DESTROY_AUTHORIZATION_PHRASE,
    TERRAFORM_DIR,
)

APPLY_COMMAND = ["apply", "-input=false", "-auto-approve"]
DESTROY_COMMAND = ["destroy", "-input=false", "-auto-approve"]


class AuthorizationError(RuntimeError):
    """A frase de autorização não foi apresentada."""


def run_terraform(args: list[str]) -> int:
    """Executa o binário do Terraform no diretório da pilha.

    Credenciais não são impressas nem colocadas na linha de comando.
    """
    completed = subprocess.run(
        ["terraform", *args],
        cwd=TERRAFORM_DIR,
        check=False,
    )
    return completed.returncode


def apply_infrastructure(*, authorize: str | None) -> int:
    _require_phrase(
        authorize,
        APPLY_AUTHORIZATION_PHRASE,
        "O apply não foi executado",
    )
    return run_terraform(APPLY_COMMAND)


def destroy_infrastructure(*, authorize: str | None) -> int:
    _require_phrase(
        authorize,
        DESTROY_AUTHORIZATION_PHRASE,
        "O destroy não foi executado",
    )
    return run_terraform(DESTROY_COMMAND)


def provision(*, authorize: str | None) -> int:
    """Inicializa, valida e planeja. O apply só ocorre com a frase exata."""
    for args in (
        ["init", "-input=false"],
        ["validate"],
        ["plan", "-input=false"],
    ):
        code = run_terraform(args)
        if code != 0:
            return code
    if authorize is None:
        print(
            "O apply não foi executado. Nenhum recurso AWS foi criado. "
            "A criação de recursos pagos exige o argumento "
            f"--authorize {APPLY_AUTHORIZATION_PHRASE}."
        )
        return 0
    return apply_infrastructure(authorize=authorize)


def cleanup(*, authorize: str | None) -> int:
    """Mostra o plano de destruição. O destroy só ocorre com a frase exata."""
    if authorize is None:
        print(
            "O destroy não foi executado. Nenhum recurso AWS foi destruído. "
            "A destruição exige o argumento "
            f"--authorize {DESTROY_AUTHORIZATION_PHRASE}."
        )
        init_code = run_terraform(["init", "-input=false"])
        if init_code != 0:
            return init_code
        return run_terraform(["plan", "-destroy", "-input=false"])
    return destroy_infrastructure(authorize=authorize)


def _require_phrase(provided: str | None, expected: str, action: str) -> None:
    if provided != expected:
        raise AuthorizationError(
            f"{action}. A frase de autorização não confere e nenhum "
            "comando destrutivo ou pago foi enviado ao Terraform."
        )
