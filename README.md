# Security Detection Engine

Модульная система для анализа событий информационной безопасности, обнаружения подозрительной активности и выявления потенциальных угроз.

Планируемые источники данных:

- Linux Authentication Logs
- Windows Event Logs и Sysmon
- PCAP-файлы и сетевой трафик

## Текущее состояние

- **Core**: базовая структура проекта, конфигурация приложения и общая модель нормализованного события безопасности `SecurityEvent`.
- **Linux SSH Authentication Log Analyzer**: чтение Linux auth logs, разбор событий SSH-аутентификации и их преобразование в `SecurityEvent`.
- **Detection Engine**: проверка нормализованных событий на соответствие YAML-правилам обнаружения и формирование алертов.
- **Network Analyzer**: чтение PCAP-файлов, извлечение метаданных пакетов (IPv4, TCP, UDP, ICMP) и их нормализация в `SecurityEvent`.
- **Windows Event Log Analyzer**: чтение XML-экспорта Windows Security Event Log (Event ID 4624 и 4625) и нормализация событий входа в `SecurityEvent`.
- **Correlation Engine**: обнаружение упорядоченных последовательностей связанных событий во временном окне с группировкой по полям.

## Назначение Core

- Единая модель события `SecurityEvent`, независимая от источника данных.
- Загрузка конфигурации приложения из переменных окружения.
- Общие перечисления: источники событий (`EventSource`) и уровни важности (`Severity`).

## Linux SSH Authentication Log Analyzer

Анализирует записи sshd из `/var/log/auth.log` (Debian/Ubuntu) и `/var/log/secure` (RHEL):

- `Failed password ...` — неудачная аутентификация (`ssh_authentication_failed`, в том числе для invalid user);
- `Accepted password/publickey/... ...` — успешная аутентификация (`ssh_authentication_success`).

Конвейер состоит из трёх компонентов:

- `collectors` — построчное чтение файла без загрузки в память;
- `parsers` — разбор строки в структурированную запись `SshAuthRecord`;
- `normalization` — преобразование записи в `SecurityEvent`.

Точка входа — `analyze_ssh_log(path, year=..., tz=...)`. Год и часовой пояс передаются явно, так как syslog-метка времени их не содержит:

```python
from datetime import UTC
from security_detection_engine.analyzer import analyze_ssh_log

result = analyze_ssh_log("auth.log", year=2024, tz=UTC)
print(result.events, result.unsupported_lines, result.invalid_lines)
```

## Detection Engine

Проверяет `SecurityEvent` на соответствие правилам обнаружения и формирует алерты. Движок не зависит от источника событий и не работает с файлами или базой данных напрямую.

Правила описываются в YAML и валидируются через Pydantic:

```yaml
rule_id: SSH-001
name: SSH Authentication Failure
description: Detects failed SSH authentication attempts
severity: low
event_type: ssh_authentication_failed
enabled: true

conditions:
  - field: data.authentication_method
    operator: equals
    value: password
```

Поддерживаемые операторы условий: `equals`, `not_equals`, `contains`, `greater_than`, `less_than`.

```python
from security_detection_engine.detection import (
    DetectionEngine,
    load_rules_from_directory,
)

rules = load_rules_from_directory("src/security_detection_engine/rules")
engine = DetectionEngine(rules)

alerts = engine.analyze_events(result.events)
```

## Network Analyzer

Читает PCAP-файлы и преобразует пакеты IPv4/TCP/UDP/ICMP в события `network_packet_observed`. Конвейер: `reader` (последовательное чтение через `PcapReader`) → `parser` (извлечение адресов, портов, флагов TCP, размера и метки времени) → `normalizer` (преобразование в `SecurityEvent`).

```python
from security_detection_engine.network import analyze_pcap

result = analyze_pcap("traffic.pcap")
print(result.events, result.parsed_packets, result.unsupported_packets)
```

## Windows Event Log Analyzer

Читает XML-экспорт Windows Security Event Log и преобразует события входа в `SecurityEvent`: Event ID 4624 → `windows_logon_success`, Event ID 4625 → `windows_logon_failed`. Конвейер: `reader` (потоковый разбор XML через `iterparse`, пространства имён игнорируются) → `parser` (извлечение System и EventData) → `normalizer` (преобразование в `SecurityEvent`).

```python
from security_detection_engine.windows import analyze_windows_log

result = analyze_windows_log("security_events.xml")
print(result.events, result.parsed_events, result.unsupported_events)
```

## Correlation Engine

Обнаруживает упорядоченные последовательности связанных `SecurityEvent` во временном окне. События сортируются по времени, группируются по значениям полей `group_by`, внутри группы ищется подпоследовательность шагов правила (между шагами допустимы другие события). Правила описываются в YAML и переиспользуют условия `Condition` из Detection Engine:

```yaml
rule_id: CORR-SSH-001
name: SSH brute force followed by successful login
description: Failed SSH logins followed by a successful login from the same IP
severity: high
enabled: true
time_window_seconds: 300

group_by:
  - data.source_ip

steps:
  - event_type: ssh_authentication_failed
  - event_type: ssh_authentication_failed
  - event_type: ssh_authentication_failed
  - event_type: ssh_authentication_success
```

Повторяющиеся шаги выражают требование нескольких событий одного типа.

```python
from security_detection_engine.correlation import (
    CorrelationEngine,
    load_correlation_rules_from_directory,
)

rules = load_correlation_rules_from_directory(
    "src/security_detection_engine/rules/correlation"
)
alerts = CorrelationEngine(rules).analyze_events(events)
```

## Unified Event Pipeline

`Pipeline(detection_engine, correlation_engine).process(events)` принимает
любой конечный `Iterable[SecurityEvent]`, включая генератор или список
событий из `analyze_ssh_log(...).events`. Каждый вызов собирает свою партию
и передаёт её обоим движкам. Импортируйте `Pipeline` из
`security_detection_engine.pipeline`.

В `PipelineResult` поле `event_count` содержит число обработанных событий.
Списки `alerts` и `correlation_alerts` содержат срабатывания каждого движка,
а `alert_count` и `correlation_alert_count` возвращают длины этих списков.

## Storage Layer

Пакет `security_detection_engine.storage` хранит нормализованные события и
оба типа алертов через синхронный SQLAlchemy 2.x и psycopg 3.
Alembic управляет схемой PostgreSQL. Зависимости устанавливаются вместе с проектом
командой `python -m pip install -e ".[dev]"`.

Таблица `security_events` хранит UUID, timezone-aware timestamp, источник,
тип, severity, host и JSONB data. `detection_alerts` ссылается на событие
внешним ключом. `correlation_alerts` хранит интервал и JSONB group_values,
а `correlation_events` связывает алерт с UUID событий по позиции.
Первичный ключ связи состоит из UUID алерта и позиции.

Задайте `SDE_DATABASE_URL` строкой вида
`postgresql+psycopg://USER:PASSWORD@HOST:5432/DATABASE` через окружение.
Подставьте собственные значения. Подключение создаётся при обращении к БД.
Примените схему командой `python -m alembic upgrade head`.
Откат первоначальной схемы выполняется через `python -m alembic downgrade base`
и удаляет сохранённые данные.

```python
from security_detection_engine.storage import (
    PipelineResultStore,
    create_database_engine,
    create_session_factory,
    transaction,
)

engine = create_database_engine()
factory = create_session_factory(engine)
try:
    events = list(normalized_events)
    result = pipeline.process(events)
    with transaction(factory) as session:
        PipelineResultStore(session).save(events, result)
finally:
    engine.dispose()
```

В примере `normalized_events` — входные SecurityEvent, `pipeline` — настроенный
Pipeline. Репозитории `EventRepository`, `AlertRepository` и
`CorrelationAlertRepository` принимают Session. Их методы `save()`, а также
`EventRepository.save_many()` выполняют flush. Вызывающий код управляет
транзакцией через `transaction(factory)` либо `with session.begin()`.
Исключения обрабатываются за пределами контекста транзакции.
Ошибка откатывает всю партию. UUID ссылок проверяются внешними ключами,
события могут уже присутствовать в БД.

Повторный UUID вызывает SQLAlchemy IntegrityError. Это относится и к повторной
отправке идентичного объекта. Для ссылок на уже сохранённые события передавайте
в store только новые события, а в PipelineResult указывайте их количество.
Сами алерты должны иметь новые UUID.

`get(uuid)` возвращает доменную Pydantic-модель либо None.
`list(limit=100, offset=0)` сортирует по timestamp и UUID.
Для событий доступны фильтры source, event_type, start_timestamp,
end_timestamp. Временные границы включительные, с обязательным часовым поясом.

Для интеграционных тестов создайте отдельную PostgreSQL-базу, например
`createdb sde_test`, и задайте `SDE_TEST_DATABASE_URL` с драйвером
`postgresql+psycopg`. У тестового пользователя должно быть право создавать
схемы в этой базе. Используйте выделенную тестовую БД.
Тесты создают временную схему, применяют миграции и удаляют схему после проверки.

- Все тесты — `python -m pytest`.
- PostgreSQL — `python -m pytest -m postgresql`.
- Проверки без PostgreSQL — `python -m pytest -m "not postgresql"`.

Без SDE_TEST_DATABASE_URL PostgreSQL-тесты пропускаются. При заданном URL
ошибки подключения считаются провалом тестов.

Хранение пакетное. JSON-совместимые значения сохраняются через сериализацию
Pydantic в JSON, UUID и datetime внутри data/group_values становятся строками.
PostgreSQL сохраняет момент времени, исходное смещение часового пояса
при чтении может измениться. Пагинация через offset при конкурентных вставках
может смещаться. Обновление и удаление объектов через репозитории пока отсутствуют.

## REST API

API использует FastAPI и синхронный SQLAlchemy. Установите зависимости через
`python -m pip install -e ".[dev]"`. Задайте `SDE_DATABASE_URL` для базы
приложения через окружение. Для локальной тестовой базы с паролем в
`%APPDATA%\postgresql\pgpass.conf` команды PowerShell выглядят так.

```powershell
$env:SDE_DATABASE_URL = 'postgresql+psycopg://sde_test_user@127.0.0.1:5432/sde_test'
python -m alembic upgrade head
python -m uvicorn security_detection_engine.api.app:app --host 127.0.0.1 --port 8000
```

Engine, фабрика Session и Pipeline создаются в lifespan приложения.
Каждый запрос получает отдельную Session, которая закрывается после запроса.
Правила загружаются при запуске из встроенной директории `rules`.
Её можно переопределить через `SDE_RULES_DIRECTORY`, содержащую обычные
YAML-правила и поддиректорию `correlation`. Ошибки конфигурации и правил
прерывают запуск. PostgreSQL проверяется при обращении к нему.
Применение миграций выполняется отдельно от запуска API.

| Метод | Маршрут | Результат |
|---|---|---|
| GET | /health | Статус приложения и версия |
| GET | /health/ready | Проверка SELECT 1 в PostgreSQL |
| POST | /analyze | Анализ и атомарное сохранение партии |
| GET | /events | Список событий |
| GET | /events/{event_id} | Событие по UUID |
| GET | /alerts | Список обычных алертов |
| GET | /alerts/{alert_id} | Обычный алерт по UUID |
| GET | /correlation-alerts | Список корреляционных алертов |
| GET | /correlation-alerts/{alert_id} | Корреляционный алерт по UUID |

Swagger UI доступен по `http://127.0.0.1:8000/docs`.
В нём можно отправить POST /analyze со следующим JSON.

```json
{
  "events": [
    {
      "timestamp": "2026-11-23T12:00:00Z",
      "source": "linux",
      "event_type": "ssh_authentication_success",
      "data": {"source_ip": "192.0.2.10"}
    }
  ]
}
```

Ответ для этого события имеет следующий вид.

```json
{
  "event_count": 1,
  "alerts": [],
  "correlation_alerts": [],
  "alert_count": 0,
  "correlation_alert_count": 0
}
```

Пустая партия допускается, максимальный размер — 1000 событий.
UUID можно передать явно, иначе он генерируется моделью события.
Каждый POST обрабатывает самостоятельную партию. События и алерты сохраняются
одной транзакцией через PipelineResultStore. Commit завершается перед
успешным ответом. При ошибке вся партия откатывается.

Списки возвращаются JSON-массивами. Параметры `limit` (1–1000, по умолчанию
100) и `offset` (>=0, по умолчанию 0) доступны всем спискам.
Например, `GET /events?source=linux&event_type=ssh_authentication_failed&limit=10&offset=0`.
Дополнительные фильтры событий `start_time` и `end_time` принимают
timezone-aware ISO timestamps с включительными границами.
Начало диапазона должно предшествовать концу либо совпадать с ним.

Ошибки параметров и входных событий возвращают 422, отсутствующий объект — 404,
повторный UUID — 409, недоступность БД — 503. Некорректные для хранения данные
возвращают 400, остальные ошибки хранения — 500. Ответы БД содержат безопасное
общее описание. SQL, параметры подключения и трассировки клиенту не передаются.

API предназначен для локального или доверенного окружения и работает
без аутентификации. Ограничение партии применяется к числу событий,
размер JSON-полей в байтах отдельно не ограничен. Анализ выполняется синхронно,
пагинация наследует ограничения Storage Layer. Обнаружение потери ответа
после commit и автоматическое повторение запроса остаются ответственностью
клиента. Повторная отправка тех же UUID возвращает 409.

API-тесты используют FastAPI TestClient. Команды запуска.

```powershell
python -m pytest tests/test_api.py
$env:SDE_TEST_DATABASE_URL = 'postgresql+psycopg://sde_test_user@127.0.0.1:5432/sde_test'
python -m pytest tests/test_api_postgresql.py
python -m pytest
```

PostgreSQL-тесты применяют миграции к временной схеме в выделенной тестовой
базе и удаляют эту схему после проверки. Подмена зависимостей доступна через
`app.dependency_overrides` для `get_session`, `get_pipeline` и
`get_api_settings` из `security_detection_engine.api.dependencies`.

## Технологии

- Python 3.11
- Pydantic 2 / pydantic-settings — модели данных, валидация, конфигурация
- PyYAML — загрузка правил обнаружения
- Scapy — чтение и разбор PCAP-файлов
- pytest — тестирование
- Ruff — проверка и форматирование кода

## Требования к окружению

- Python 3.11
- Виртуальное окружение (рекомендуется)

## Установка

```bash
python -m venv .venv
source .venv/Scripts/activate  # Windows (Git Bash)
# source .venv/bin/activate    # Linux/macOS

pip install -e ".[dev]"
```

## Конфигурация

Настройки задаются переменными окружения с префиксом `SDE_`:

| Переменная      | По умолчанию                 | Описание           |
|-----------------|------------------------------|--------------------|
| `SDE_APP_NAME`  | `security-detection-engine`  | Название приложения |
| `SDE_VERSION`   | `0.1.0`                      | Версия             |
| `SDE_LOG_LEVEL` | `INFO`                       | Уровень логирования |

## Запуск тестов

```bash
pytest
```

## Проверка кода

```bash
ruff check .
ruff format --check .
```

## Структура проекта

```
security-detection-engine/
├── src/
│   └── security_detection_engine/
│       ├── __init__.py
│       ├── analyzer.py        # Точка входа анализа SSH-логов
│       ├── config.py          # Конфигурация приложения
│       ├── collectors/        # Чтение лог-файлов
│       ├── correlation/       # Correlation Engine
│       ├── detection/         # Detection Engine и загрузка правил
│       ├── models/            # Модель SecurityEvent
│       ├── network/           # Network Analyzer (PCAP)
│       ├── normalization/     # Преобразование в SecurityEvent
│       ├── parsers/           # Разбор строк логов
│       ├── rules/             # YAML-правила обнаружения
│       └── windows/           # Windows Event Log Analyzer (XML)
├── tests/                     # Автоматизированные тесты
├── .gitignore
├── pyproject.toml
└── README.md
```
