"""Saúde da API e do SQLite. Rota pública, sem credencial."""

from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from remediation.api.deps import get_session, get_settings_dep
from remediation.config import Settings
from remediation.db import ping_database
from remediation.schemas.health import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health(
    settings: Annotated[Settings, Depends(get_settings_dep)],
    session: Annotated[Session, Depends(get_session)],
) -> HealthResponse | JSONResponse:
    try:
        ping_database(session)
    except SQLAlchemyError:
        return JSONResponse(
            status_code=503,
            content=HealthResponse(
                status="degraded",
                version=settings.app_version,
                database="error",
            ).model_dump(),
        )
    return HealthResponse(status="ok", version=settings.app_version, database="ok")
