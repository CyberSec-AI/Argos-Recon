from __future__ import annotations

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

from app.schemas.types import HTTPRequestArtifactV1, TLSArtifactV1, SignalV1, DNSArtifactV1, CMSArtifactV1
from app.schemas.finding_v1 import FindingV1

class FindingCountsV1(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

class RunReportSNR(BaseModel):
    signals_total: int
    findings_total: int
    requests_total: int

class RunReportSummaryV1(BaseModel):
    finding_counts: FindingCountsV1
    top_findings: List[str] = Field(default_factory=list)
    snr: RunReportSNR
    verdict: str

class RunReportArtifactsV1(BaseModel):
    requests: List[HTTPRequestArtifactV1] = Field(default_factory=list)
    tls: List[TLSArtifactV1] = Field(default_factory=list)
    dns: Optional[DNSArtifactV1] = None
    # NOUVEAU : Champ CMS natif
    cms: Optional[CMSArtifactV1] = None

class RunReportV1(BaseModel):
    schema_version: str = "runreport.v1"
    run_id: str
    engine: Dict[str, Any]
    time: Dict[str, Any]
    operator: Dict[str, Any]
    scope: Dict[str, Any]
    summary: RunReportSummaryV1
    delta: Dict[str, Any]
    artifacts: RunReportArtifactsV1
    signals: List[SignalV1] = Field(default_factory=list)
    findings: List[FindingV1] = Field(default_factory=list)