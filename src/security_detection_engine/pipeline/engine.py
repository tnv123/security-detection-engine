from collections.abc import Iterable

from security_detection_engine.correlation import CorrelationEngine
from security_detection_engine.detection import DetectionEngine
from security_detection_engine.models import SecurityEvent
from security_detection_engine.pipeline.models import PipelineResult


class Pipeline:
    """Пакетный анализ нормализованных событий обоими движками."""

    def __init__(
        self, detection_engine: DetectionEngine, correlation_engine: CorrelationEngine
    ) -> None:
        self._detection_engine = detection_engine
        self._correlation_engine = correlation_engine

    def process(self, events: Iterable[SecurityEvent]) -> PipelineResult:
        """Проверяет одну партию событий и возвращает результаты обоих движков."""
        batch = list(events)
        return PipelineResult(
            event_count=len(batch),
            alerts=self._detection_engine.analyze_events(batch),
            correlation_alerts=self._correlation_engine.analyze_events(batch),
        )
