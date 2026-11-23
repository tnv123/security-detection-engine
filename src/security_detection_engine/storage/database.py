from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from security_detection_engine.config import get_settings


def create_database_engine(url: str | None = None) -> Engine:
    """Создаёт Engine с отложенным подключением к PostgreSQL."""
    database_url = url or get_settings().database_url
    if not database_url:
        raise ValueError("Задайте SDE_DATABASE_URL")
    engine = create_engine(database_url, pool_pre_ping=True)
    if engine.dialect.name != "postgresql":
        engine.dispose()
        raise ValueError("Storage Layer требует PostgreSQL")
    return engine


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Создаёт фабрику независимых сессий."""
    return sessionmaker(engine, expire_on_commit=False)


@contextmanager
def transaction(factory: sessionmaker[Session]) -> Iterator[Session]:
    """Открывает сессию и транзакцию с rollback при ошибке."""
    with factory.begin() as session:
        yield session
