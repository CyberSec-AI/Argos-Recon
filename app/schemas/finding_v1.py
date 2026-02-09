from __future__ import annotations

from typing import List, Optional, Literal, Dict, Any
from pydantic import BaseModel, Field
from app.schemas.types import Severity, Confidence


class FindingScoreV1(BaseModel):
    total: int
    threshold: int
    model: str = "points.v1"


class FindingTargetRefV1(BaseModel):
    target_id: str
    input: str
    canonical_url: str


class FindingEvidenceRefV1(BaseModel):
    evidence_id: str
    type: str
    ref: Dict[str, Any]
    snippet: str


class FindingSignalRefV1(BaseModel):
    signal_id: str
    value: bool
    evidence_refs: List[str] = Field(default_factory=list)
    artifact_ref: Optional[str] = None


class BurpNextActionV1(BaseModel):
    type: str
    title: str
    suggested_paths: List[str] = Field(default_factory=list)
    caution: Optional[str] = None


class BurpArtifactsV1(BaseModel):
    urls: List[str] = Field(default_factory=list)
    requests: List[str] = Field(default_factory=list)  # request_ids
    next_actions: List[BurpNextActionV1] = Field(default_factory=list)


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
    reasoning: Dict[str, Any] = Field(default_factory=dict)

    signals: List[FindingSignalRefV1] = Field(default_factory=list)
    evidence: List[FindingEvidenceRefV1] = Field(default_factory=list)

    burp_artifacts: BurpArtifactsV1 = Field(default_factory=BurpArtifactsV1)
