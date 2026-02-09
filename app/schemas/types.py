from __future__ import annotations

from typing import Dict, List, Optional, Literal
from pydantic import BaseModel, Field


Severity = Literal["info", "low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]


class TimingsMs(BaseModel):
    dns: int = 0
    tcp: int = 0
    tls: int = 0
    ttfb: int = 0
    total: int = 0


class TargetV1(BaseModel):
    target_id: str
    input: str
    canonical_url: str
    host: str
    resolved_ips: List[str] = Field(default_factory=list)
    ports: List[int] = Field(default_factory=list)


class TLSArtifactV1(BaseModel):
    tls_id: str
    target_id: str
    observed_host: str
    ip: str
    port: int
    cn: Optional[str] = None
    san: List[str] = Field(default_factory=list)
    issuer_dn: Optional[str] = None
    serial_number: Optional[str] = None
    self_signed: bool = False
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    hash: Optional[str] = None
    protocol: Optional[str] = None
    cipher: Optional[str] = None
    alpn: Optional[str] = None
    error: Optional[str] = None


class HTTPRequestArtifactV1(BaseModel):
    request_id: str
    target_id: str
    
    url: str
    effective_url: str 
    
    host: str
    ip: str
    port: int
    tls: bool
    protocol: str = "HTTP/1.1"
    method: str
    
    raw: str
    raw_encoding: str = "base64"

    response_raw: Optional[str] = None
    response_raw_encoding: Optional[str] = None
    response_truncated: bool = False
    response_hash: Optional[str] = None 
    
    response_analysis_snippet: Optional[str] = None

    status_code: Optional[int] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    timings_ms: TimingsMs = Field(default_factory=TimingsMs)
    tags: List[str] = Field(default_factory=list)


class SignalV1(BaseModel):
    signal_id: str
    source: Literal["tls", "http", "tech"]
    target_id: str
    value: bool
    weight: int = 1
    signal_confidence: float = 0.9
    evidence_refs: List[str] = Field(default_factory=list)
    artifact_ref: Optional[str] = None