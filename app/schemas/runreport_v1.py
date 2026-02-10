from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# --- Sous-modèles ---


class FindingCountsV1(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class RunReportSNR(BaseModel):
    """Signal-to-Noise Ratio metrics."""

    signals_total: int
    findings_total: int
    requests_total: int


class RunReportSummaryV1(BaseModel):
    finding_counts: FindingCountsV1
    top_findings: List[str] = Field(default_factory=list)
    snr: Optional[RunReportSNR] = None
    verdict: str = "unknown"


class RunReportArtifactsV1(BaseModel):
    requests: List[Any] = Field(default_factory=list)
    tls: List[Any] = Field(default_factory=list)
    dns: Optional[Any] = None
    cms: Optional[Any] = None


# --- Modèle d'erreur pour le rapport ---
class ReportErrorV1(BaseModel):
    component: str
    error_type: str
    message: str
    timestamp: str


# --- Modèle Principal ---
class RunReportV1(BaseModel):
    schema_version: str = "runreport.v1"
    run_id: str
    engine: Dict[str, str]
    time: Dict[str, Any]
    operator: Dict[str, str]
    scope: Dict[str, Any]
    summary: RunReportSummaryV1

    # La section errors pour le débogage
    errors: List[ReportErrorV1] = Field(default_factory=list)

    delta: Optional[Dict[str, Any]] = None
    artifacts: RunReportArtifactsV1
    signals: List[Any] = Field(default_factory=list)
    findings: List[Any] = Field(default_factory=list)
