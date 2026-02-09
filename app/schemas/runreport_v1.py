from __future__ import annotations

from typing import Dict, List, Optional, Any, Literal
from pydantic import BaseModel, Field

from app.schemas.types import TargetV1, TLSArtifactV1, HTTPRequestArtifactV1, SignalV1
from app.schemas.finding_v1 import FindingV1


class EngineInfoV1(BaseModel):
    name: str = "recon-assistant"
    engine_version: str = "0.1.0"
    build: str = "dev"
    profile: str = "pentest_pro"  # CORRIGÉ : plus d'espace
    mode: str = "low_noise"


class TimeInfoV1(BaseModel):
    started_at: str
    finished_at: str
    duration_ms: int


class GuardrailsV1(BaseModel):
    max_requests: int = 50
    timeouts_ms: Dict[str, int] = Field(default_factory=lambda: {"dns": 2000, "tls": 4000, "http": 8000})
    ssrf_protection: Dict[str, bool] = Field(default_factory=lambda: {
        "block_private_ranges": True,
        "block_link_local": True,
        "block_loopback": True
    })
    leak_checks_mode: Literal["off", "opt_in", "smart_gated"] = "opt_in"
    response_raw_policy: Literal["off", "on_small", "on_all"] = "on_small"
    response_raw_max_bytes: int = 262144  # 256KB


class ScopeV1(BaseModel):
    intent: str = "recon"
    targets: List[TargetV1]
    guardrails: GuardrailsV1 = Field(default_factory=GuardrailsV1)


class SummaryV1(BaseModel):
    finding_counts: Dict[str, int] = Field(default_factory=lambda: {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
    })
    top_findings: List[str] = Field(default_factory=list)
    snr: Dict[str, int] = Field(default_factory=lambda: {"signals_total": 0, "findings_total": 0, "requests_total": 0})
    verdict: str = ""


class DeltaV1(BaseModel):
    delta_ready: bool = True
    fingerprint_algo: str = "v1:sha256"
    normalization: Dict[str, Any] = Field(default_factory=lambda: {
        "version": "norm.v1",
        "url_normalization": "lowercase_host, strip_default_ports, ensure_trailing_slash",
        "header_normalization": "lowercase_keys, trim_values",
        "tls_normalization": "sorted_san, normalized_issuer_dn"
    })
    target_fingerprint: Optional[str] = None
    run_fingerprint: Optional[str] = None
    finding_fingerprints: List[Dict[str, str]] = Field(default_factory=list)


class ArtifactsV1(BaseModel):
    requests: List[HTTPRequestArtifactV1] = Field(default_factory=list)
    tls: List[TLSArtifactV1] = Field(default_factory=list)


class RunReportV1(BaseModel):
    schema_version: str = "runreport.v1"
    run_id: str
    engine: EngineInfoV1 = Field(default_factory=EngineInfoV1)
    time: TimeInfoV1
    operator: Dict[str, Any] = Field(default_factory=dict)
    scope: ScopeV1
    summary: SummaryV1 = Field(default_factory=SummaryV1)
    delta: DeltaV1 = Field(default_factory=DeltaV1)

    artifacts: ArtifactsV1 = Field(default_factory=ArtifactsV1)
    signals: List[SignalV1] = Field(default_factory=list)
    findings: List[FindingV1] = Field(default_factory=list)
