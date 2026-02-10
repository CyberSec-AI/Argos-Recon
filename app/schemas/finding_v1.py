from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from app.schemas.types import Confidence, Severity


# Références
class FindingTargetRefV1(BaseModel):
    target_id: str
    input: str
    canonical_url: str


class FindingEvidenceRefV1(BaseModel):
    evidence_id: str
    type: str
    ref: Dict[str, Any]
    snippet: Optional[str] = None


class FindingSignalRefV1(BaseModel):
    signal_id: str
    description: Optional[str] = None


class FindingScoreV1(BaseModel):
    total: int
    threshold: int = 1
    model: str = "risk_v1"


# Modèle Principal
class FindingV1(BaseModel):
    schema_version: str = "finding.v1"
    finding_id: str
    playbook_id: str
    title: str
    summary: str
    severity: Severity
    confidence: Confidence
    score: FindingScoreV1
    target: FindingTargetRefV1
    reasoning: Dict[str, str]
    signals: List[FindingSignalRefV1] = Field(default_factory=list)
    evidence: List[FindingEvidenceRefV1] = Field(default_factory=list)
    burp_artifacts: Dict[str, Any] = Field(default_factory=dict)
