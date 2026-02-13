from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field

# --- Enums ---
Severity = Literal["critical", "high", "medium", "low", "info"]
Confidence = Literal["high", "medium", "low"]


class TargetV1(BaseModel):
    target_id: str
    input: str
    canonical_url: str
    host: str
    resolved_ips: List[str] = Field(default_factory=list)
    ports: List[int] = Field(default_factory=list)
    scheme: Optional[str] = "https"
    port: Optional[int] = None


class TimingsMs(BaseModel):
    total: int = 0
    dns: Optional[int] = None
    connect: Optional[int] = None
    handshake: Optional[int] = None


class TLSArtifactV1(BaseModel):
    tls_id: str
    target_id: str
    observed_host: str
    ip: str
    port: int
    protocol: Optional[str] = None
    cipher: Optional[str] = None
    cn: Optional[str] = None
    not_after: Optional[str] = None
    issuer_o: Optional[str] = None
    peer_cert_sha256: Optional[str] = None
    error: Optional[str] = None
    timings_ms: TimingsMs = Field(default_factory=TimingsMs)


class HTTPRequestArtifactV1(BaseModel):
    request_id: str
    target_id: str
    url: str
    effective_url: str
    host: str
    ip: str
    port: int
    tls: bool = False
    method: str
    status_code: Optional[int] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    response_truncated: bool = False
    response_analysis_snippet: Optional[str] = None
    error: Optional[str] = None
    timings_ms: TimingsMs = Field(default_factory=TimingsMs)


class DNSArtifactV1(BaseModel):
    dns_id: str
    target_id: str
    domain: str
    domain_checked_for_email_auth: Optional[str] = None
    registrable_domain_method: Literal["naive", "psl"] = "naive"
    a: List[str] = Field(default_factory=list)
    aaaa: List[str] = Field(default_factory=list)
    mx: List[str] = Field(default_factory=list)
    ns: List[str] = Field(default_factory=list)
    txt: List[str] = Field(default_factory=list)
    dmarc: List[str] = Field(default_factory=list)
    cname: Optional[str] = None
    warnings: List[str] = Field(default_factory=list)
    error: Optional[str] = None
    timings_ms: TimingsMs = Field(default_factory=TimingsMs)


class CMSArtifactV1(BaseModel):
    cms_id: str
    target_id: str
    detected_cms: str = "unknown"
    confidence: Confidence = "low"
    timings_ms: TimingsMs = Field(default_factory=TimingsMs)


class SignalV1(BaseModel):
    signal_id: str
    source: str
    target_id: str
    value: Any
    signal_confidence: float = 1.0
