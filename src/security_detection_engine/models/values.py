from decimal import Decimal
from math import isfinite
from typing import Any


def finite_values(value: Any) -> Any:
    """Проверяет ключи, числа и глубину до преобразования данных в JSON.

    Допускается до 64 вложенных контейнеров для безопасной сериализации.
    """
    active: set[int] = set()

    def visit(item: Any, depth: int = 0) -> None:
        if isinstance(item, float) and not isfinite(item):
            raise ValueError("Требуется конечное число")
        if isinstance(item, Decimal) and not item.is_finite():
            raise ValueError("Требуется конечное число")
        if isinstance(item, (dict, list, tuple, set, frozenset)):
            if depth >= 64:
                raise ValueError("Превышена допустимая глубина данных")
            identity = id(item)
            if identity in active:
                raise ValueError("Циклическое значение")
            active.add(identity)
            if isinstance(item, dict):
                for key, child in item.items():
                    visit(key, depth + 1)
                    visit(child, depth + 1)
            else:
                for child in item:
                    visit(child, depth + 1)
            active.remove(identity)

    visit(value)
    return value
