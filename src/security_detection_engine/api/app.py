from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import (
    DataError,
    IntegrityError,
    OperationalError,
    SQLAlchemyError,
    TimeoutError,
)

from security_detection_engine.api.routes import alerts, analysis, events, health
from security_detection_engine.config import Settings, get_settings
from security_detection_engine.correlation import (
    CorrelationEngine,
    load_correlation_rules_from_directory,
)
from security_detection_engine.detection import (
    DetectionEngine,
    load_rules_from_directory,
)
from security_detection_engine.pipeline import Pipeline
from security_detection_engine.storage import (
    create_database_engine,
    create_session_factory,
)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Создаёт приложение с ресурсами, ограниченными его жизненным циклом."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        config = settings if settings is not None else get_settings()
        app.state.settings = config
        app.state.pipeline = Pipeline(
            DetectionEngine(load_rules_from_directory(config.rules_directory)),
            CorrelationEngine(
                load_correlation_rules_from_directory(
                    config.rules_directory / "correlation"
                )
            ),
        )
        engine = create_database_engine(config.database_url)
        app.state.session_factory = create_session_factory(engine)
        try:
            yield
        finally:
            engine.dispose()

    app = FastAPI(title="Security Detection Engine", lifespan=lifespan)

    @app.exception_handler(SQLAlchemyError)
    async def database_error(request: Request, exc: SQLAlchemyError) -> JSONResponse:
        if isinstance(exc, (OperationalError, TimeoutError)) or getattr(
            exc, "connection_invalidated", False
        ):
            return JSONResponse(
                status_code=503, content={"detail": "База данных недоступна"}
            )
        if (
            isinstance(exc, IntegrityError)
            and getattr(exc.orig, "sqlstate", None) == "23505"
        ):
            return JSONResponse(
                status_code=409, content={"detail": "UUID уже существует"}
            )
        if isinstance(exc, DataError):
            return JSONResponse(
                status_code=400, content={"detail": "Данные не могут быть сохранены"}
            )
        return JSONResponse(
            status_code=500, content={"detail": "Ошибка хранения данных"}
        )

    app.include_router(health.router)
    app.include_router(analysis.router)
    app.include_router(events.router)
    app.include_router(alerts.router)
    return app


app = create_app()
