"""Dependências da API. A chave de laboratório não é registrada em log."""

import secrets
from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, Header, Request
from sqlalchemy.orm import Session

from remediation.api.errors import APIError
from remediation.config import Settings
from remediation.db import session_scope


def get_settings_dep(request: Request) -> Settings:
    return request.app.state.settings


def get_session(request: Request) -> Iterator[Session]:
    yield from session_scope(request.app.state.session_factory)


def api_key_is_valid(provided: str | None, expected: str) -> bool:
    if not provided or not expected:
        return False
    return secrets.compare_digest(provided, expected)


def require_api_key(
    settings: Annotated[Settings, Depends(get_settings_dep)],
    x_api_key: Annotated[str | None, Header()] = None,
) -> None:
    if not api_key_is_valid(x_api_key, settings.lab_api_key):
        raise APIError(
            status_code=401,
            code="unauthorized",
            message="Credencial de laboratório ausente ou inválida.",
        )
