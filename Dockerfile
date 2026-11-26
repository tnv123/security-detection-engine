FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY pyproject.toml constraints-runtime.txt ./
RUN python -c "import subprocess, sys, tomllib; dependencies = tomllib.load(open('pyproject.toml', 'rb'))['project']['dependencies']; subprocess.run([sys.executable, '-m', 'pip', 'install', '--no-cache-dir', '-c', 'constraints-runtime.txt', *dependencies], check=True)"

COPY src/ ./src/
RUN python -m pip install --no-cache-dir --no-deps . \
    && rm -rf /app/src /app/build \
    && useradd --create-home --uid 10001 app

COPY alembic.ini ./
COPY migrations/ ./migrations/

USER app
EXPOSE 8000

CMD ["python", "-m", "uvicorn", "security_detection_engine.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
