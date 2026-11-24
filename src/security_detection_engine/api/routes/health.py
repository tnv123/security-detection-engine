from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import text

from security_detection_engine.api.dependencies import (
    SessionDependency,
    get_api_settings,
)
from security_detection_engine.config import Settings

router = APIRouter()


@router.get("/health")
def health(settings: Annotated[Settings, Depends(get_api_settings)]) -> dict[str, str]:
    """Проверяет доступность приложения."""
    return {"status": "ok", "version": settings.version}


@router.get("/health/ready")
def ready(session: SessionDependency) -> dict[str, str]:
    """Проверяет выполнение запроса к PostgreSQL."""
    session.execute(text("SELECT 1"))
    return {"status": "ready"}
