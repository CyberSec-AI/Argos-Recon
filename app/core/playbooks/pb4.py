from __future__ import annotations

from typing import List, Optional

import ulid

from app.schemas.finding_v1 import (
    EvidenceV1,
    FindingScoreV1,
    FindingTargetRefV1,
    FindingV1,
)
from app.schemas.types import DNSArtifactV1, HTTPRequestArtifactV1, TargetV1


def evaluate_pb4(
    dns: DNSArtifactV1, target: TargetV1, http_artifacts: List[HTTPRequestArtifactV1]
) -> Optional[FindingV1]:
    """
    PB4: Détection de Subdomain Takeover (CNAME pointant vers un service mort).
    """
    if not dns.cname:
        return None

    # Simulation simple : si CNAME contient un bucket cloud mais que le HTTP baseline est en 404
    cloud_providers = ["s3.amazonaws.com", "azurewebsites.net", "github.io", "herokudns.com"]
    is_cloud = any(p in dns.cname.lower() for p in cloud_providers)

    baseline_404 = any(
        a.status_code == 404 for a in http_artifacts if a.url == target.canonical_url
    )

    if is_cloud and baseline_404:
        return FindingV1(
            finding_id=str(ulid.new()),
            playbook_id="PB4_SUBDOMAIN_TAKEOVER",
            title="Potential Subdomain Takeover",
            summary=f"CNAME {dns.cname} points to a cloud provider but returns 404.",
            severity="high",
            confidence="medium",
            score=FindingScoreV1(total=8, threshold=1, model="risk_v1"),
            target=FindingTargetRefV1(
                target_id=target.target_id, input=target.input, canonical_url=target.canonical_url
            ),
            reasoning={
                "why_it_matters": "An attacker could claim the orphaned resource and host malicious content.",
                "analyst_notes": "Verify if the cloud resource is truly available for registration.",
            },
            evidence=[
                EvidenceV1(
                    evidence_id=f"ev_takeover_{ulid.new()}",
                    type="dns_cname",
                    ref={"cname": dns.cname},
                    snippet=f"CNAME: {dns.cname}",
                )
            ],
        )

    return None
