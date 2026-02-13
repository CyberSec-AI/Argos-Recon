from __future__ import annotations

from typing import List, Optional

import ulid

from app.schemas.finding_v1 import (
    EvidenceV1,
    FindingScoreV1,
    FindingSignalRefV1,
    FindingTargetRefV1,
    FindingV1,
)
from app.schemas.types import Severity, SignalV1, TargetV1


def evaluate_pb1(
    signals: List[SignalV1], target: TargetV1, tls_id: str, request_id: str
) -> Optional[FindingV1]:
    problem_signals = [s for s in signals if s.source == "tls" and s.value]

    if not problem_signals:
        return None

    score_val = 0
    severity_val: Severity = "low"

    has_expired = any(s.signal_id == "tls.is_expired" for s in problem_signals)
    has_mismatch = any(s.signal_id == "tls.subject_mismatch" for s in problem_signals)

    if has_expired or has_mismatch:
        score_val += 7
        severity_val = "high"
    else:
        score_val += 2
        severity_val = "low"

    evidence_list = []
    signal_refs = []

    for s in problem_signals:
        evidence_list.append(
            EvidenceV1(
                evidence_id=f"ev_{str(ulid.new())}",
                type="signal_ref",
                ref={"signal_id": s.signal_id},
                snippet=f"Issue detected: {s.signal_id}",
            )
        )

        signal_refs.append(
            FindingSignalRefV1(
                signal_id=s.signal_id, description=f"Detection triggered: {s.signal_id}"
            )
        )

    return FindingV1(
        finding_id=str(ulid.new()),
        playbook_id="PB1_TLS_WEAKNESS",
        title="TLS Configuration Issues",
        summary="TLS weaknesses detected.",
        severity=severity_val,
        confidence="high",
        score=FindingScoreV1(total=score_val, threshold=1, model="risk_v1"),
        target=FindingTargetRefV1(
            target_id=target.target_id,
            input=target.input,
            canonical_url=target.canonical_url,
        ),
        reasoning={
            "why_it_matters": "Encryption integrity is crucial for data privacy.",
            "analyst_notes": "Fix TLS configuration to match best practices.",
        },
        signals=signal_refs,
        evidence=evidence_list,
    )
