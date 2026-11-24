from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query

from security_detection_engine.api.dependencies import SessionDependency
from security_detection_engine.api.schemas import Pagination
from security_detection_engine.correlation import CorrelationAlert
from security_detection_engine.detection import Alert
from security_detection_engine.storage import (
    AlertRepository,
    CorrelationAlertRepository,
)

router = APIRouter()


@router.get("/alerts", response_model=list[Alert])
def list_alerts(
    session: SessionDependency,
    page: Annotated[Pagination, Query()],
) -> list[Alert]:
    """Возвращает страницу обычных алертов."""
    return AlertRepository(session).list(**page.model_dump())


@router.get("/alerts/{alert_id}", response_model=Alert)
def get_alert(alert_id: UUID, session: SessionDependency) -> Alert:
    """Возвращает обычный алерт по UUID."""
    alert = AlertRepository(session).get(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Алерт не найден")
    return alert


@router.get("/correlation-alerts", response_model=list[CorrelationAlert])
def list_correlation_alerts(
    session: SessionDependency,
    page: Annotated[Pagination, Query()],
) -> list[CorrelationAlert]:
    """Возвращает страницу корреляционных алертов."""
    return CorrelationAlertRepository(session).list(**page.model_dump())


@router.get("/correlation-alerts/{alert_id}", response_model=CorrelationAlert)
def get_correlation_alert(
    alert_id: UUID, session: SessionDependency
) -> CorrelationAlert:
    """Возвращает корреляционный алерт по UUID."""
    alert = CorrelationAlertRepository(session).get(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Алерт не найден")
    return alert
