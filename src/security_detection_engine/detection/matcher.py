from typing import Any

from security_detection_engine.detection.models import (
    Condition,
    DetectionRule,
    Operator,
)
from security_detection_engine.models import SecurityEvent


def match_rule(rule: DetectionRule, event: SecurityEvent) -> bool:
    """Проверяет, соответствует ли событие правилу обнаружения."""
    if event.event_type != rule.event_type:
        return False
    event_data = event.model_dump()
    return all(match_condition(event_data, condition) for condition in rule.conditions)


def match_condition(event_data: dict[str, Any], condition: Condition) -> bool:
    """Проверяет одно условие; отсутствующее поле означает отсутствие совпадения."""
    found, actual = resolve_field(event_data, condition.field)
    if not found:
        return False
    return _apply_operator(condition.operator, actual, condition.value)


def resolve_field(data: dict[str, Any], field: str) -> tuple[bool, Any]:
    """Извлекает значение поля по пути вида 'data.source_ip'."""
    current: Any = data
    for part in field.split("."):
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _equal(left: Any, right: Any) -> bool:
    if isinstance(left, bool) != isinstance(right, bool):
        return False
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(
            _equal(a, b) for a, b in zip(left, right)
        )
    if isinstance(left, dict) and isinstance(right, dict):
        return left.keys() == right.keys() and all(
            _equal(left[k], right[k]) for k in left
        )
    return left == right


def _apply_operator(operator: Operator, actual: Any, expected: Any) -> bool:
    """Применяет оператор к значениям.

    Несовместимость типов не приводит к исключению — условие просто
    считается невыполненным.
    """
    if operator is Operator.EQUALS:
        return _equal(actual, expected)
    if operator is Operator.NOT_EQUALS:
        return not _equal(actual, expected)
    if operator is Operator.CONTAINS:
        if not isinstance(actual, (str, list)):
            return False
        if isinstance(actual, list):
            return any(_equal(item, expected) for item in actual)
        try:
            return expected in actual
        except TypeError:
            return False
    if operator is Operator.GREATER_THAN:
        return _is_number(actual) and _is_number(expected) and actual > expected
    if operator is Operator.LESS_THAN:
        return _is_number(actual) and _is_number(expected) and actual < expected
    raise ValueError(f"неподдерживаемый оператор: {operator}")


def _is_number(value: Any) -> bool:
    # bool является подклассом int, но числом для сравнения не считается
    return isinstance(value, (int, float)) and not isinstance(value, bool)
