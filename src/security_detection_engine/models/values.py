from decimal import Decimal
from math import isfinite
from typing import Any


def finite_values(value: Any) -> Any:
    """Проверяет числа во вложенных данных до преобразования в JSON."""
    active: set[int] = set()

    def visit(item: Any) -> None:
        if isinstance(item, float) and not isfinite(item):
            raise ValueError("Требуется конечное число")
        if isinstance(item, Decimal) and not item.is_finite():
            raise ValueError("Требуется конечное число")
        if isinstance(item, (dict, list, tuple, set, frozenset)):
            identity = id(item)
            if identity in active:
                raise ValueError("Циклическое значение")
            active.add(identity)
            for child in item.values() if isinstance(item, dict) else item:
                visit(child)
            active.remove(identity)

    visit(value)
    return value
