"""Aplicação FastAPI da Fase 1. Sem IA, GitLab, AWS ou executor."""

from fastapi import FastAPI

from remediation.api.errors import register_exception_handlers
from remediation.api.routes.health import router as health_router
from remediation.config import Settings, get_settings
from remediation.db import create_db_engine, init_db, session_factory_for


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved = settings or get_settings()
    engine = create_db_engine(resolved.database_url)
    init_db(engine)
    app = FastAPI(
        title="Remediação assistida por IA",
        version=resolved.app_version,
        description=(
            "API de laboratório para experimentos de remediação. "
            "A Fase 1 expõe saúde, persistência local e a máquina de estados. "
            "Não executa scripts."
        ),
    )
    app.state.settings = resolved
    app.state.engine = engine
    app.state.session_factory = session_factory_for(engine)
    register_exception_handlers(app)
    app.include_router(health_router)
    return app


def __getattr__(name: str) -> FastAPI:
    if name == "app":
        application = create_app()
        globals()["app"] = application
        return application
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
