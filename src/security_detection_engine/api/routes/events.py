from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query

from security_detection_engine.api.dependencies import SessionDependency
from security_detection_engine.api.schemas import EventFilters
from security_detection_engine.models import SecurityEvent
from security_detection_engine.storage import EventRepository

router = APIRouter()


@router.get("/events", response_model=list[SecurityEvent])
def list_events(
    session: SessionDependency,
    filters: Annotated[EventFilters, Query()],
) -> list[SecurityEvent]:
    """Возвращает страницу событий с фильтрами."""
    return EventRepository(session).list(
        limit=filters.limit,
        offset=filters.offset,
        source=filters.source,
        event_type=filters.event_type,
        start_timestamp=filters.start_time,
        end_timestamp=filters.end_time,
    )


@router.get("/events/{event_id}", response_model=SecurityEvent)
def get_event(event_id: UUID, session: SessionDependency) -> SecurityEvent:
    """Возвращает событие по UUID."""
    event = EventRepository(session).get(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Событие не найдено")
    return event
