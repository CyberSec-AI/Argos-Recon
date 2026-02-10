from __future__ import annotations
import ulid
from typing import Optional, List
from app.schemas.types import SignalV1, TargetV1
from app.schemas.finding_v1 import FindingV1, FindingScoreV1, FindingTargetRefV1, FindingEvidenceRefV1

def evaluate_pb1(
    signals: List[SignalV1], 
    target: TargetV1, 
    tls_id: str, 
    request_id: str
) -> Optional[FindingV1]:
    
    problem_signals = [s for s in signals if s.source == "tls" and not s.value]
    if not problem_signals: return None

    score_val = 5
    severity = "medium"

    evidence_list = []
    for s in problem_signals:
        evidence_list.append(FindingEvidenceRefV1(
            evidence_id=f"ev_{str(ulid.new())}",
            type="signal_ref",
            ref={"signal_id": s.signal_id},
            snippet=f"Issue detected: {s.signal_id}"
        ))

    return FindingV1(
        finding_id=str(ulid.new()),
        playbook_id="PB1_TLS_WEAKNESS",
        title="TLS Configuration Issues",
        summary="TLS weaknesses detected.",
        severity=severity,
        confidence="high",
        score=FindingScoreV1(total=score_val, threshold=1, model="risk_v1"),
        target=FindingTargetRefV1(
            target_id=target.target_id,
            input=target.input,
            canonical_url=target.canonical_url
        ),
        reasoning={"why_it_matters": "Encryption.", "analyst_notes": "Fix TLS."},
        signals=[s.signal_id for s in problem_signals],
        evidence=evidence_list,
        burp_artifacts={"urls": []}
    )