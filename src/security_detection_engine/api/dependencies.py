from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from security_detection_engine.config import Settings
from security_detection_engine.pipeline import Pipeline


def get_api_settings(request: Request) -> Settings:
    """Возвращает конфигурацию запущенного приложения."""
    return request.app.state.settings


def get_pipeline(request: Request) -> Pipeline:
    """Возвращает Pipeline, созданный при запуске приложения."""
    return request.app.state.pipeline


def get_session(request: Request) -> Iterator[Session]:
    """Открывает отдельную Session для запроса и гарантирует её закрытие."""
    with request.app.state.session_factory() as session:
        yield session


SessionDependency = Annotated[Session, Depends(get_session)]
PipelineDependency = Annotated[Pipeline, Depends(get_pipeline)]
