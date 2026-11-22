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
