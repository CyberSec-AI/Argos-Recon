from __future__ import annotations

from typing import List, Optional

import ulid

from app.schemas.finding_v1 import (
    FindingEvidenceRefV1,
    FindingScoreV1,
    FindingTargetRefV1,
    FindingV1,
)
from app.schemas.types import HTTPRequestArtifactV1, SignalV1, TargetV1

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
]


def evaluate_pb2(
    signals: List[SignalV1],
    target: TargetV1,
    http_artifacts: List[HTTPRequestArtifactV1],
) -> Optional[FindingV1]:

    if not http_artifacts:
        return None

    baseline = http_artifacts[0]
    headers_lower = {k.lower(): v for k, v in baseline.headers.items()}

    missing = [h for h in SECURITY_HEADERS if h.lower() not in headers_lower]

    if not missing:
        return None

    evidence = []
    # ... (le reste est inchangé)
    for m in missing:
        evidence.append(
            FindingEvidenceRefV1(
                evidence_id=f"ev_{str(ulid.new())}",
                type="header_missing",
                ref={"header": m},
                snippet=f"Header {m} is missing",
            )
        )

    return FindingV1(
        finding_id=str(ulid.new()),
        playbook_id="PB2_MISSING_HEADERS",
        title="Missing Security Headers",
        summary=f"Missing {len(missing)} recommended security headers.",
        severity="low",
        confidence="high",
        score=FindingScoreV1(total=len(missing), threshold=1, model="risk_v1"),
        target=FindingTargetRefV1(
            target_id=target.target_id,
            input=target.input,
            canonical_url=target.canonical_url,
        ),
        reasoning={
            "why_it_matters": "Browser security.",
            "analyst_notes": "Add headers.",
        },
        signals=[],
        evidence=evidence,
        burp_artifacts={"urls": []},
    )
