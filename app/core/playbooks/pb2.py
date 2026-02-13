from __future__ import annotations

from typing import List, Optional

import ulid

from app.schemas.finding_v1 import (
    EvidenceV1,
    FindingScoreV1,
    FindingTargetRefV1,
    FindingV1,
)
from app.schemas.types import HTTPRequestArtifactV1, Severity, SignalV1, TargetV1


def evaluate_pb2(
    signals: List[SignalV1], target: TargetV1, http_artifacts: List[HTTPRequestArtifactV1]
) -> Optional[FindingV1]:
    """
    PB2: Analyse de la présence des headers de sécurité (HSTS, CSP, etc.).
    """
    missing_headers = [
        s.value for s in signals if s.source == "http_header" and s.signal_id == "header_missing"
    ]

    if not missing_headers:
        return None

    # Calcul de sévérité simple
    critical_missing = {"Content-Security-Policy", "Strict-Transport-Security"}
    has_critical = any(h in critical_missing for h in missing_headers)

    severity: Severity = "medium" if has_critical else "low"
    score_val = 5 if has_critical else 2

    evidence_list = [
        EvidenceV1(
            evidence_id=f"ev_header_{ulid.new()}",
            type="header_missing",
            ref={"header": h},
            snippet=f"Header {h} is missing",
        )
        for h in missing_headers
    ]

    return FindingV1(
        finding_id=str(ulid.new()),
        playbook_id="PB2_SECURITY_HEADERS",
        title="Missing Security Headers",
        summary=f"Detected {len(missing_headers)} missing security headers.",
        severity=severity,
        confidence="high",
        score=FindingScoreV1(total=score_val, threshold=1, model="risk_v1"),
        target=FindingTargetRefV1(
            target_id=target.target_id, input=target.input, canonical_url=target.canonical_url
        ),
        reasoning={
            "why_it_matters": "Security headers protect against XSS, clickjacking, and MITM attacks.",
            "analyst_notes": "Prioritize CSP and HSTS implementation.",
        },
        evidence=evidence_list,
    )
