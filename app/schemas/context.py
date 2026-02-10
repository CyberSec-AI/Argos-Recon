from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from app.schemas.finding_v1 import FindingV1
from app.schemas.types import (
    CMSArtifactV1,
    DNSArtifactV1,
    HTTPRequestArtifactV1,
    SignalV1,
    TargetV1,
    TLSArtifactV1,
)


class ScanError(BaseModel):
    component: str
    error_type: str
    message: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ScanContext(BaseModel):
    run_id: str
    target: TargetV1
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    dns: Optional[DNSArtifactV1] = None
    tls: Optional[TLSArtifactV1] = None
    http: List[HTTPRequestArtifactV1] = Field(default_factory=list)
    cms: Optional[CMSArtifactV1] = None

    signals: List[SignalV1] = Field(default_factory=list)
    findings: List[FindingV1] = Field(default_factory=list)

    errors: List[ScanError] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def add_error(self, component: str, error_type: str, message: str):
        self.errors.append(
            ScanError(component=component, error_type=error_type, message=message)
        )
