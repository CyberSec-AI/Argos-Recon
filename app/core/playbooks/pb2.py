from __future__ import annotations
import ulid
from typing import Optional, List
from app.schemas.types import SignalV1, HTTPRequestArtifactV1, TargetV1
from app.schemas.finding_v1 import FindingV1, FindingScoreV1, FindingTargetRefV1, FindingEvidenceRefV1

SECURITY_HEADERS = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"]

def evaluate_pb2(
    signals: List[SignalV1], 
    target: TargetV1, 
    http_artifacts: List[HTTPRequestArtifactV1]
) -> Optional[FindingV1]:
    
    if not http_artifacts: return None
    baseline = http_artifacts[0]
    
    raw_headers = baseline.headers or {}
    if isinstance(raw_headers, dict):
        iterable = raw_headers.items()
    else:
        iterable = raw_headers
        
    headers_lower = {str(k).lower(): str(v) for k, v in iterable}
    
    missing = [h for h in SECURITY_HEADERS if h.lower() not in headers_lower]
    if not missing: return None
        
    evidence = []
    for m in missing:
        evidence.append(FindingEvidenceRefV1(
            evidence_id=f"ev_{str(ulid.new())}",
            type="missing_header",
            ref={"header": m},
            snippet=f"Missing: {m}"
        ))

    return FindingV1(
        finding_id=str(ulid.new()),
        playbook_id="PB2_MISSING_HEADERS",
        title=f"Missing Security Headers ({len(missing)})",
        summary="Headers missing.",
        severity="low",
        confidence="high",
        score=FindingScoreV1(total=len(missing), threshold=1, model="risk_v1"),
        target=FindingTargetRefV1(
            target_id=target.target_id,
            input=target.input,
            canonical_url=target.canonical_url
        ),
        reasoning={"why_it_matters": "Defense in depth.", "analyst_notes": "Add headers."},
        signals=[],
        evidence=evidence,
        burp_artifacts={"urls": []}
    )