from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import TypeVar

import yaml
from pydantic import BaseModel, ValidationError

from security_detection_engine.detection.models import DetectionRule

_SUPPORTED_SUFFIXES = (".yaml", ".yml")

ModelT = TypeVar("ModelT", bound=BaseModel)


class RuleLoadError(Exception):
    """Ошибка загрузки или валидации YAML-правила."""


def load_rule(path: str | Path) -> DetectionRule:
    """Загружает одно правило обнаружения из YAML-файла."""
    return load_rule_file(Path(path), DetectionRule)


def load_rules_from_directory(directory: str | Path) -> list[DetectionRule]:
    """Загружает все YAML-правила из директории.

    Файлы с другими расширениями игнорируются.
    """
    return load_rule_directory(Path(directory), DetectionRule)


def load_rule_file(path: Path, model: type[ModelT]) -> ModelT:
    """Загружает правило заданной модели из YAML-файла."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RuleLoadError(f"не удалось прочитать файл правила {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise RuleLoadError(f"некорректный YAML в файле {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise RuleLoadError(f"файл {path} не содержит описание правила")

    try:
        return model.model_validate(raw)
    except ValidationError as exc:
        raise RuleLoadError(f"некорректное правило в файле {path}: {exc}") from exc


def unique_rules(rules: Iterable[ModelT]) -> Iterator[ModelT]:
    """Проверяет идентификаторы до фильтрации отключённых правил."""
    seen = set()
    for rule in rules:
        if rule.rule_id in seen:
            raise RuleLoadError(f"Повторный rule_id: {rule.rule_id}")
        seen.add(rule.rule_id)
        yield rule


def load_rule_directory(directory: Path, model: type[ModelT]) -> list[ModelT]:
    """Загружает все YAML-правила заданной модели из директории.

    Файлы с другими расширениями игнорируются.
    """
    if not directory.is_dir():
        raise RuleLoadError(f"директория правил не найдена: {directory}")

    return list(
        unique_rules(
            load_rule_file(path, model)
            for path in sorted(directory.iterdir())
            if path.is_file() and path.suffix.lower() in _SUPPORTED_SUFFIXES
        )
    )
