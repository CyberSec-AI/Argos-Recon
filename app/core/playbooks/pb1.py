from __future__ import annotations

from typing import Optional, List

import ulid
from app.schemas.finding_v1 import FindingV1, FindingScoreV1, FindingTargetRefV1, FindingSignalRefV1, FindingEvidenceRefV1, BurpArtifactsV1, BurpNextActionV1
from app.schemas.types import SignalV1


def evaluate_pb1(signals: List[SignalV1], target: dict, tls_id: str, request_id: str) -> Optional[FindingV1]:
    """
    Playbook 1: Exposed Non-Production Environment
    Trigger: requires 1 TLS signal AND 1 HTTP signal (heterogeneity constraint), score >= 2
    """
    tls_mismatch = next((s for s in signals if s.signal_id == "tls.subject_mismatch" and s.value), None)
    http_verbose = next((s for s in signals if s.signal_id == "http.header.verbose" and s.value), None)

    score_total = 0
    if tls_mismatch:
        score_total += 1
    if http_verbose:
        score_total += 1

    # Heterogeneity constraint: must have TLS + HTTP
    if not (tls_mismatch and http_verbose and score_total >= 2):
        return None

    finding_id = str(ulid.new())

    evidence = [
        FindingEvidenceRefV1(
            evidence_id="ev_tls_subject",
            type="tls",
            ref={"tls_id": tls_id},
            snippet="CN/SAN contains non-production naming (dev/staging/test/internal/local)."
        ),
        FindingEvidenceRefV1(
            evidence_id="ev_http_hdr_verbose",
            type="http_headers",
            ref={"request_id": request_id},
            snippet="Verbose backend stack versions exposed via response headers (e.g., Server / X-Powered-By)."
        )
    ]

    return FindingV1(
        finding_id=finding_id,
        playbook_id="PB1_EXPOSED_NONPROD_ENV",
        title="Potential Exposed Non-Production Environment",
        summary="Cross-layer indicators suggest a staging/dev environment is publicly reachable.",
        severity="medium",
        confidence="high",
        score=FindingScoreV1(total=score_total, threshold=2, model="points.v1"),
        target=FindingTargetRefV1(
            target_id=target["target_id"],
            input=target["input"],
            canonical_url=target["canonical_url"]
        ),
        reasoning={
            "why_it_matters": "Non-production targets are often less monitored and may expose debug/admin features or weaker controls.",
            "correlation": [
                "TLS identity includes non-production naming.",
                "HTTP headers expose precise backend stack versions."
            ],
            "analyst_notes": "Treat as a strategic lead; validate with a minimal set of staging/debug endpoints (low-noise)."
        },
        signals=[
            FindingSignalRefV1(signal_id="tls.subject_mismatch", value=True, evidence_refs=["ev_tls_subject"]),
            FindingSignalRefV1(signal_id="http.header.verbose", value=True, evidence_refs=["ev_http_hdr_verbose"], artifact_ref=request_id)
        ],
        evidence=evidence,
        burp_artifacts=BurpArtifactsV1(
            urls=[target["canonical_url"]],
            requests=[request_id],
            next_actions=[
                BurpNextActionV1(
                    type="burp_repeater",
                    title="Probe a minimal set of staging/debug endpoints",
                    suggested_paths=["/debug", "/_debugbar", "/status", "/actuator"],
                    caution="Low-noise only; do not brute force."
                )
            ]
        )
    )
