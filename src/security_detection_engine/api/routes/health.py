from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from security_detection_engine.api.dependencies import (
    SessionDependency,
    get_api_settings,
)
from security_detection_engine.config import Settings
from security_detection_engine.storage.revision import EXPECTED_REVISION

router = APIRouter()


@router.get("/health")
def health(settings: Annotated[Settings, Depends(get_api_settings)]) -> dict[str, str]:
    """Проверяет доступность приложения."""
    return {"status": "ok", "version": settings.version}


@router.get("/health/ready")
def ready(session: SessionDependency) -> dict[str, str]:
    """Проверяет выполнение запроса к PostgreSQL."""
    try:
        revisions = (
            session.execute(
                text(
                    "SELECT version_num FROM alembic_version WHERE "
                    "to_regclass('security_events') IS NOT NULL AND "
                    "to_regclass('detection_alerts') IS NOT NULL AND "
                    "to_regclass('correlation_alerts') IS NOT NULL AND "
                    "to_regclass('correlation_events') IS NOT NULL"
                )
            )
            .scalars()
            .all()
        )
    except SQLAlchemyError:
        raise HTTPException(503, "База данных недоступна") from None
    if revisions != [EXPECTED_REVISION]:
        raise HTTPException(503, "Схема базы данных не готова")
    return {"status": "ready"}
