from __future__ import annotations
from typing import List, Optional, Dict, Any, Literal
from pydantic import BaseModel, Field

# --- Enums (Indispensables pour finding_v1.py) ---
Severity = Literal["critical", "high", "medium", "low", "info"]
Confidence = Literal["high", "medium", "low"]

# --- Modèles de base ---

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
    """Modèle structuré pour les temps de réponse."""
    total: int = 0
    dns: Optional[int] = None
    connect: Optional[int] = None
    handshake: Optional[int] = None

# --- Artefacts ---

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
    
    error: Optional[str] = None
    # Utilisation stricte du modèle TimingsMs
    timings_ms: TimingsMs = Field(default_factory=TimingsMs)

class HTTPRequestArtifactV1(BaseModel):
    request_id: str
    target_id: str
    url: str
    effective_url: Optional[str] = None
    host: Optional[str] = None
    ip: Optional[str] = None
    port: Optional[int] = None
    tls: bool = False
    method: str
    status_code: Optional[int] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    
    response_truncated: bool = False
    response_analysis_snippet: Optional[str] = None
    raw: Optional[str] = None 
    
    error: Optional[str] = None
    # Utilisation stricte du modèle TimingsMs
    timings_ms: TimingsMs = Field(default_factory=TimingsMs)

class DNSArtifactV1(BaseModel):
    dns_id: str
    target_id: str
    domain: str
    a: List[str] = Field(default_factory=list)
    aaaa: List[str] = Field(default_factory=list)
    cname: Optional[str] = None
    mx: List[str] = Field(default_factory=list)
    ns: List[str] = Field(default_factory=list)
    txt: List[str] = Field(default_factory=list)
    dmarc: List[str] = Field(default_factory=list)
    soa: Optional[str] = None
    
    error: Optional[str] = None
    # Utilisation stricte du modèle TimingsMs
    timings_ms: TimingsMs = Field(default_factory=TimingsMs)

class CMSArtifactV1(BaseModel):
    cms_id: str
    target_id: str
    detected_cms: str = "unknown"
    version: Optional[str] = None
    confidence: str = "low"
    evidence: List[str] = Field(default_factory=list)
    # On garde int ici pour compatibilité simple (ou TimingsMs si tu mets à jour cms.py)
    timings_ms: int = 0 

class SignalV1(BaseModel):
    signal_id: str
    source: str
    target_id: str
    value: Any
    weight: int = 1
    signal_confidence: float = 1.0
    evidence_refs: List[Any] = Field(default_factory=list)
    artifact_ref: Optional[Any] = None