from alembic import context

from security_detection_engine.config import get_settings
from security_detection_engine.storage.database import create_database_engine
from security_detection_engine.storage.models import Base

target_metadata = Base.metadata

if context.is_offline_mode():
    url = get_settings().database_url
    if not url:
        raise ValueError("Задайте SDE_DATABASE_URL")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()
else:
    engine = create_database_engine()
    try:
        with engine.connect() as connection:
            context.configure(connection=connection, target_metadata=target_metadata)
            with context.begin_transaction():
                context.run_migrations()
    finally:
        engine.dispose()
