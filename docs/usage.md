# Использование

Python-примеры запускаются после установки пакета по
[development.md](development.md). Исходные данные синтетические.
Публичного CLI для запуска файловых анализаторов в проекте нет.

## SSH

analyze_ssh_log(path, *, year, tz) возвращает LogAnalysisResult с events,
invalid_lines и unsupported_lines. Количество прочитанных строк равно
сумме этих двух счётчиков и len(events). После распознавания syslog-префикса
неполная Failed/Accepted-запись считается invalid. Нераспознанный префикс
или сообщение другого типа учитывается как unsupported.

Поддерживается OpenSSH syslog с Failed/Accepted, методом, пользователем,
адресом и портом. Допускаются invalid user и согласованные хвосты ssh2,
включая SHA256 fingerprint. Год и часовой пояс передаются явно,
месяцы распознаются независимо от локали. IP сохраняется канонически.
Год при переходе через Новый год автоматически не пересчитывается.
Journald ISO и отпечаток ключа MD5 не поддерживаются.

```python
from datetime import UTC
from pathlib import Path
from tempfile import TemporaryDirectory
from security_detection_engine.analyzer import analyze_ssh_log

with TemporaryDirectory() as directory:
    path = Path(directory) / "auth.log"
    path.write_text(
        "Nov 16 10:00:00 host sshd[1234]: Failed password for root "
        "from 192.0.2.10 port 54321 ssh2\n",
        encoding="utf-8",
    )
    ssh = analyze_ssh_log(path, year=2024, tz=UTC)
    assert (len(ssh.events), ssh.invalid_lines, ssh.unsupported_lines) == (1, 0, 0)
```

Неудача создаёт ssh_authentication_failed с low, успех —
ssh_authentication_success с severity=None. Host берётся из syslog.
В data входят username, `source_ip`, source_port, authentication_method,
process_id, invalid_user. Встроенное правило SSH-001 реагирует на Failed password.

## Windows XML

analyze_windows_log(path) возвращает WindowsAnalysisResult с events,
total_events, parsed_events, invalid_events и unsupported_events.
Сумма трёх категорий равна total_events.
4624 преобразуется в windows_logon_success, 4625 — в windows_logon_failed
с low. Остальные Event ID относятся к unsupported. Поле `SystemTime` должно содержать часовой пояс,
Computer переходит в host, пустой Computer становится None.
В data сохраняются системные `event_id` и provider, а также строковые EventData
с исходными именами. Повторные именованные Data и имена event_id/provider
классифицируются как invalid.

```python
from pathlib import Path
from tempfile import TemporaryDirectory
from security_detection_engine.windows import analyze_windows_log

with TemporaryDirectory() as directory:
    path = Path(directory) / "events.xml"
    path.write_text(
        "<Events><Event><System><EventID>4625</EventID>"
        '<TimeCreated SystemTime="2024-11-16T10:00:00Z"/>'
        '<Computer>host</Computer><Provider Name="synthetic"/>'
        '</System><EventData><Data Name="TargetUserName">root</Data>'
        "</EventData></Event></Events>",
        encoding="utf-8",
    )
    windows = analyze_windows_log(path)
    assert (windows.total_events, windows.parsed_events) == (1, 1)
    assert windows.events[0].data["TargetUserName"] == "root"
```

Анализатор читает XML-экспорт. Бинарный EVTX и Sysmon в текущий набор
форматов не входят. Повреждённая структура XML вызывает исключение,
продолжение чтения после неё не гарантируется.

## PCAP

analyze_pcap(path) возвращает NetworkAnalysisResult с events,
total_packets, parsed_packets, invalid_packets и unsupported_packets.
Поддерживается внешний IPv4 с непосредственно относящимся к нему TCP, UDP
или ICMP. IPv6, IP-туннели и IPv4-фрагменты относятся к unsupported.
ICMP с диагностическим вложением сохраняет атрибуты внешнего ICMP.
Анализатор извлекает метаданные из сохранённых пакетов. Захват трафика в реальном времени,
анализ полезной нагрузки и восстановление потоков не поддерживаются.

```python
from pathlib import Path
from tempfile import TemporaryDirectory
from scapy.layers.inet import IP, TCP
from scapy.utils import wrpcap
from security_detection_engine.network import analyze_pcap

with TemporaryDirectory() as directory:
    path = Path(directory) / "traffic.pcap"
    packet = IP(src="192.0.2.10", dst="192.0.2.20") / TCP(
        sport=54321, dport=22, flags="S"
    )
    packet.time = 1731751200
    wrpcap(str(path), [packet])
    network = analyze_pcap(path)
    assert (network.total_packets, network.parsed_packets) == (1, 1)
    assert network.events[0].data["destination_port"] == 22
```

Событие network_packet_observed имеет UTC `timestamp`, source=network,
host=None, severity=None. Data содержит `source_ip`, destination_ip, protocol,
source_port, destination_port, packet_size и tcp_flags.
У ICMP порты и flags равны None. Ошибки открытия и чтения файла передаются
вызывающему коду. Корректно читаемый пакет с недопустимыми значениями
учитывается как invalid.

## Правила обнаружения

Обязательные поля DetectionRule — `rule_id`, name, description, `severity`,
event_type. Conditions по умолчанию пуст, `enabled` по умолчанию True.
Все условия объединяются через AND. Пустые условия означают проверку event_type.
Каждое условие содержит field, operator и value. Путь к вложенному полю,
например data.source_ip, проходит по словарям. Пустые сегменты пути запрещены.

Существующее правило src/security_detection_engine/rules/ssh_authentication_failed.yaml
имеет следующий смысл.

```yaml
rule_id: SSH-001
name: SSH Authentication Failure
description: Detects failed SSH authentication attempts
severity: low
event_type: ssh_authentication_failed
conditions:
  - field: data.authentication_method
    operator: equals
    value: password
enabled: true
```

| Оператор | Поведение |
|---|---|
| equals / not_equals | Равенство с разделением bool и чисел, в том числе во вложенных списках/словарях |
| contains | Подстрока для строки, элемент для списка с той же семантикой равенства |
| greater_than / less_than | Сравнение int и конечного float, исключая bool |

Строки автоматически к числам не приводятся. Int и float могут быть численно
равны. Отсутствующее поле не совпадает, в том числе для not_equals.
Неподдерживаемые комбинации типов при contains и числовых операторах дают False.
Неконечные значения в условиях запрещены. Условия группировки корреляции
сохраняют отдельную типизированную семантику.

load_rule(path) читает один YAML через safe_load, load_rules_from_directory(path)
читает .yaml/.yml в порядке имён. Ошибки представлены RuleLoadError.
Повторные `rule_id` в одном наборе отклоняются, включая отключённые правила.
Конструкторы движков также проверяют уникальность до фильтрации enabled.
ID Detection и Correlation проверяются в своих отдельных наборах.

## Правила корреляции

CorrelationRule содержит `rule_id`, name, description, `severity`,
time_window_seconds > 0, непустой `group_by` и не менее двух steps.
Enabled по умолчанию True. Каждый CorrelationStep задаёт `event_type` и список
conditions с той же AND-семантикой. Повторение шага выражает несколько событий.
Счётчик повторений отдельным оператором не реализован.

Ниже существующее правило rules/correlation/ssh_brute_force_then_success.yaml
с исходными полями.

```yaml
rule_id: CORR-SSH-001
name: SSH brute force followed by successful login
description: >-
  Several failed SSH password logins followed by a successful login
  from the same source IP within the time window
severity: high
enabled: true
time_window_seconds: 300

group_by:
  - data.source_ip

steps:
  - event_type: ssh_authentication_failed
    conditions:
      - field: data.authentication_method
        operator: equals
        value: password
  - event_type: ssh_authentication_failed
    conditions:
      - field: data.authentication_method
        operator: equals
        value: password
  - event_type: ssh_authentication_failed
    conditions:
      - field: data.authentication_method
        operator: equals
        value: password
  - event_type: ssh_authentication_success
```

`CorrelationAlert` содержит correlation_id, поля правила, `severity`,
`timestamp`, start_timestamp, end_timestamp, упорядоченный event_ids и group_values.
UUID внутри одного алерта уникальны. Timestamp совпадает с end_timestamp.
Алгоритм группировки, окно и пример пропуска жадного поиска описаны в
[architecture.md](architecture.md).

## Pipeline и отдельное сохранение

Этот пример создаёт четыре нормализованных события, анализирует их и получает
три обычных алерта и один корреляционный.

```python
from datetime import UTC, datetime, timedelta
from importlib.resources import files
from security_detection_engine.models import SecurityEvent
from security_detection_engine.detection import (
    DetectionEngine,
    load_rules_from_directory,
)
from security_detection_engine.correlation import (
    CorrelationEngine,
    load_correlation_rules_from_directory,
)
from security_detection_engine.pipeline import Pipeline

rules = files("security_detection_engine") / "rules"
pipeline = Pipeline(
    DetectionEngine(load_rules_from_directory(str(rules))),
    CorrelationEngine(
        load_correlation_rules_from_directory(str(rules / "correlation"))
    ),
)
events = [
    SecurityEvent(
        timestamp=datetime(2024, 11, 16, tzinfo=UTC) + timedelta(seconds=i),
        source="linux",
        event_type="ssh_authentication_failed"
        if i < 3
        else "ssh_authentication_success",
        data={"source_ip": "192.0.2.10", "authentication_method": "password"},
    )
    for i in range(4)
]
result = pipeline.process(iter(events))
assert (result.event_count, result.alert_count, result.correlation_alert_count) == (
    4,
    3,
    1,
)
```

Pipeline принимает конечный Iterable[`SecurityEvent`], в том числе генератор.
Пустой вход допустим. Возвращаемые alerts и correlation_alerts имеют отдельные
типы. Вызов process выполняет анализ без записи.
Для сохранения результата предыдущего примера задайте `SDE_DATABASE_URL`
для роли `sde_runtime` и выполните следующий блок один раз для этой партии.

```python
from security_detection_engine.storage import (
    PipelineResultStore,
    create_database_engine,
    create_session_factory,
    transaction,
)

engine = create_database_engine()
try:
    factory = create_session_factory(engine)
    with transaction(factory) as session:
        PipelineResultStore(session).save(events, result)
finally:
    engine.dispose()
```

Повторная запись тех же UUID вызывает `IntegrityError` и откат транзакции.
EventRepository предоставляет save, save_many, get и list с фильтрами source,
`event_type`, start_timestamp, end_timestamp. AlertRepository и
CorrelationAlertRepository предоставляют save, get и list.
Метод `get` возвращает модель либо `None`. Метод `list` использует `limit=100` и `offset=0`
по умолчанию. Транзакцией управляет вызывающий код.
Ссылки на ранее сохранённые события допустимы при записи только новых событий.

## REST API

Подробные схемы доступны в [Swagger UI](http://127.0.0.1:8000/docs),
[ReDoc](http://127.0.0.1:8000/redoc) и /openapi.json.
HTTP-пример отправки приведён в [README](../README.md).

| Метод и путь | Ввод | Успешный результат | Основные ошибки |
|---|---|---|---|
| GET /health | Нет | 200, status и version | Ошибка доступности процесса |
| GET /health/ready | Нет | 200, status=ready | 503 |
| POST /analyze | JSON с events | 200, `PipelineResult` | 400, 409, 413, 415, 422, 500, 503 |
| GET /events | Фильтры и пагинация | 200, массив `SecurityEvent` | 422, 500, 503 |
| GET /events/{`event_id`} | UUID | 200, `SecurityEvent` | 404, 422, 500, 503 |
| GET /alerts | Пагинация | 200, массив Alert | 422, 500, 503 |
| GET /alerts/{alert_id} | UUID | 200, Alert | 404, 422, 500, 503 |
| GET /correlation-alerts | Пагинация | 200, массив `CorrelationAlert` | 422, 500, 503 |
| GET /correlation-alerts/{alert_id} | UUID | 200, `CorrelationAlert` | 404, 422, 500, 503 |

AnalyzeRequest имеет вид {"events": [...]}. Обязательные поля события —
`timestamp` с часовым поясом, source и event_type. Event_id генерируется,
`severity` и host необязательны, data по умолчанию пуст. Source принимает
linux, windows и network. `PipelineResult` возвращает `event_count`, alerts,
correlation_alerts, `alert_count` и correlation_alert_count.

Обычный Alert содержит alert_id, `rule_id`, rule_name, description, `severity`,
`event_id` и timestamp. Поля корреляционного алерта перечислены выше.
Возвращаемый data отражает сохранённое JSON-представление.

Все списки поддерживают limit от 1 до 1000, по умолчанию 100, и offset >= 0,
по умолчанию 0. /events дополнительно принимает source, `event_type`,
start_time и end_time. Временные границы включительные и задаются с часовым поясом,
start_time должен быть <= end_time. Для + в смещении времени используйте
URL-кодирование, например curl --get --data-urlencode. Порядок — `timestamp`,
затем UUID. Offset может смещаться при конкурентных вставках.

HTTP допускает пустую партию, максимум 1000 событий. `SDE_MAX_REQUEST_BODY_BYTES`
по умолчанию равен 5242880. Middleware учитывает фактический поток байтов,
включая chunked-запрос. Превышение даёт 413 до Pipeline и записи.
Сжатые тела не поддерживаются, Content-Encoding кроме identity даёт 415.
Некорректный Content-Length даёт 400.
Предел 64 контейнера с учётом корневого действует в проверяемых структурах
data, значений условий и group_values. Неконечные числа и ключи отклоняются.
Глубоко вложенное JSON-тело может быть отклонено JSON-парсером с 400
раньше собственной проверки с 422.

Одинаковый UUID даёт 409 и откат всей партии. Прочие недопустимые параметры
обычно дают 422. Недопустимое значение для хранения может дать 400,
ошибка хранилища — 500, недоступность БД или схемы readiness — 503.
Ответы об ошибках скрывают SQL, параметры подключения и трассировки.
Каждый запрос использует собственную Session.

Число 1000 и HTTP-лимит байтов действуют на REST-входе.
В Python `Pipeline` принимает конечный итерируемый объект произвольного размера в пределах
доступной памяти. В Python поле `data` может содержать UUID и datetime в значениях.
HTTP JSON имеет строковые ключи и поддерживает JSON-типы.
Передаваемые поля source и host описывают заявление клиента.
Подлинность источника не проверяется. Аутентификация и авторизация отсутствуют.
