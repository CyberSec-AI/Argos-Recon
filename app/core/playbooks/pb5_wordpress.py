from __future__ import annotations

from typing import Any, Dict, List

import ulid

from app.schemas.finding_v1 import (
    EvidenceV1,
    FindingScoreV1,
    FindingTargetRefV1,
    FindingV1,
)
from app.schemas.types import CMSArtifactV1, HTTPRequestArtifactV1, TargetV1


def evaluate_pb5(
    cms: CMSArtifactV1,
    target: TargetV1,
    http_artifacts: List[HTTPRequestArtifactV1],
    cve_db: List[Dict[str, Any]],
) -> List[FindingV1]:
    """
    PB5: Analyse approfondie WordPress et détection de fuites d'utilisateurs.
    """
    findings: List[FindingV1] = []

    if cms.detected_cms != "wordpress":
        return findings

    # Détection de fuite d'utilisateurs via REST API
    user_leak = next(
        (a for a in http_artifacts if "wp-json/wp/v2/users" in a.url and a.status_code == 200), None
    )

    if user_leak:
        findings.append(
            FindingV1(
                finding_id=str(ulid.new()),
                playbook_id="PB5_WP_USER_LEAK",
                title="WordPress User Enumeration via REST API",
                summary="User accounts were discovered through the WordPress REST API.",
                severity="medium",
                confidence="high",
                score=FindingScoreV1(total=5, threshold=1, model="risk_v1"),
                target=FindingTargetRefV1(
                    target_id=target.target_id,
                    input=target.input,
                    canonical_url=target.canonical_url,
                ),
                reasoning={
                    "why_it_matters": "Exposing usernames facilitates brute-force attacks.",
                    "analyst_notes": "Restrict access to /wp-json/wp/v2/users.",
                },
                evidence=[
                    EvidenceV1(
                        evidence_id=f"ev_wp_user_{ulid.new()}",
                        type="http_response",
                        ref={"url": user_leak.url},
                        snippet=user_leak.response_analysis_snippet[:500]
                        if user_leak.response_analysis_snippet
                        else None,
                    )
                ],
            )
        )

    return findings
