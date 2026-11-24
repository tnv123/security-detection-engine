from fastapi import APIRouter

from security_detection_engine.api.dependencies import (
    PipelineDependency,
    SessionDependency,
)
from security_detection_engine.api.schemas import AnalyzeRequest
from security_detection_engine.pipeline import PipelineResult
from security_detection_engine.storage import PipelineResultStore

router = APIRouter()


@router.post("/analyze", response_model=PipelineResult)
def analyze(
    body: AnalyzeRequest,
    session: SessionDependency,
    pipeline: PipelineDependency,
) -> PipelineResult:
    """Анализирует независимую партию и атомарно сохраняет результат."""
    result = pipeline.process(body.events)
    with session.begin():
        PipelineResultStore(session).save(body.events, result)
    return result
