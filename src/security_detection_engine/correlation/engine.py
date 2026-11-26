from collections.abc import Iterable
from typing import Any

from security_detection_engine.correlation.models import (
    CorrelationAlert,
    CorrelationRule,
    CorrelationStep,
)
from security_detection_engine.detection.loader import unique_rules
from security_detection_engine.detection.matcher import (
    match_condition,
    resolve_field,
)
from security_detection_engine.models import SecurityEvent


class CorrelationEngine:
    """Обнаруживает последовательности связанных событий во временном окне.

    Обработка пакетная: события сортируются по timestamp, группируются
    по значениям полей group_by, внутри каждой группы ищется упорядоченная
    подпоследовательность шагов правила. Между совпавшими шагами могут
    находиться другие события.

    События с одинаковым timestamp сохраняют порядок входа (сортировка
    стабильна): если шаги последовательности имеют одинаковые метки времени,
    результат зависит от их порядка во входных данных.

    Поиск жадный: если кандидат выходит за временное окно, альтернативные
    последовательности с более поздним началом не перебираются.
    """

    def __init__(self, rules: Iterable[CorrelationRule]) -> None:
        self._rules = [rule for rule in unique_rules(rules) if rule.enabled]

    def analyze_events(self, events: Iterable[SecurityEvent]) -> list[CorrelationAlert]:
        """Проверяет события по всем активным правилам и возвращает алерты."""
        ordered = sorted(events, key=lambda event: event.timestamp)
        alerts = []
        for rule in self._rules:
            alerts.extend(self._apply_rule(rule, ordered))
        return alerts

    def _apply_rule(
        self, rule: CorrelationRule, events: list[SecurityEvent]
    ) -> list[CorrelationAlert]:
        groups: dict[tuple[Any, ...], list[SecurityEvent]] = {}
        for event in events:
            key = _group_key(rule, event)
            if key is not None:
                groups.setdefault(key, []).append(event)

        alerts = []
        for key, group_events in groups.items():
            for matched in _find_sequences(rule, group_events):
                alerts.append(_create_alert(rule, key, matched))
        return alerts


def _group_key(rule: CorrelationRule, event: SecurityEvent) -> tuple | None:
    """Ключ группировки; события без значений полей не группируются.

    Тип значения входит в ключ, чтобы True/1 и 1/1.0 не объединялись.
    Сложные значения (списки, словари) не поддерживаются — такие события
    исключаются из группировки.
    """
    event_data = event.model_dump()
    key = []
    for field_path in rule.group_by:
        found, value = resolve_field(event_data, field_path)
        if not found or value is None:
            return None
        if not isinstance(value, (str, int, float, bool)):
            return None
        key.append((type(value).__name__, value))
    return tuple(key)


def _find_sequences(
    rule: CorrelationRule, events: list[SecurityEvent]
) -> list[list[SecurityEvent]]:
    """Ищет упорядоченные подпоследовательности шагов в группе событий.

    Окно отсчитывается от первого события кандидата; при превышении окна
    кандидат сбрасывается, и текущее событие пробуется как начало новой
    последовательности.
    """
    sequences = []
    matched: list[SecurityEvent] = []
    step_index = 0
    for event in events:
        if step_index == 0:
            if _matches_step(rule.steps[0], event):
                matched = [event]
                step_index = 1
            continue

        elapsed = (event.timestamp - matched[0].timestamp).total_seconds()
        if elapsed > rule.time_window_seconds:
            if _matches_step(rule.steps[0], event):
                matched = [event]
                step_index = 1
            else:
                matched = []
                step_index = 0
            continue

        if _matches_step(rule.steps[step_index], event):
            matched.append(event)
            step_index += 1
            if step_index == len(rule.steps):
                sequences.append(matched)
                matched = []
                step_index = 0
    return sequences


def _matches_step(step: CorrelationStep, event: SecurityEvent) -> bool:
    if event.event_type != step.event_type:
        return False
    if not step.conditions:
        return True
    event_data = event.model_dump()
    return all(match_condition(event_data, condition) for condition in step.conditions)


def _create_alert(
    rule: CorrelationRule, key: tuple, matched: list[SecurityEvent]
) -> CorrelationAlert:
    return CorrelationAlert(
        rule_id=rule.rule_id,
        rule_name=rule.name,
        description=rule.description,
        severity=rule.severity,
        timestamp=matched[-1].timestamp,
        event_ids=[event.event_id for event in matched],
        start_timestamp=matched[0].timestamp,
        end_timestamp=matched[-1].timestamp,
        group_values={
            path: tagged[1] for path, tagged in zip(rule.group_by, key, strict=True)
        },
    )
