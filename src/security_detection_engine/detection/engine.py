from collections.abc import Iterable

from security_detection_engine.detection.loader import unique_rules
from security_detection_engine.detection.matcher import match_rule
from security_detection_engine.detection.models import Alert, DetectionRule
from security_detection_engine.models import SecurityEvent


class DetectionEngine:
    """Проверяет нормализованные события на соответствие правилам обнаружения.

    Движок не зависит от источника событий: он работает только с
    SecurityEvent и не читает логи, файлы правил и базы данных.
    """

    def __init__(self, rules: Iterable[DetectionRule]) -> None:
        self._rules = [rule for rule in unique_rules(rules) if rule.enabled]

    def analyze_event(self, event: SecurityEvent) -> list[Alert]:
        """Проверяет одно событие и возвращает список алертов."""
        return [
            self._create_alert(rule, event)
            for rule in self._rules
            if match_rule(rule, event)
        ]

    def analyze_events(self, events: Iterable[SecurityEvent]) -> list[Alert]:
        """Проверяет последовательность событий и возвращает все алерты."""
        alerts = []
        for event in events:
            alerts.extend(self.analyze_event(event))
        return alerts

    @staticmethod
    def _create_alert(rule: DetectionRule, event: SecurityEvent) -> Alert:
        return Alert(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            description=rule.description,
            severity=rule.severity,
            event_id=event.event_id,
            timestamp=event.timestamp,
        )
