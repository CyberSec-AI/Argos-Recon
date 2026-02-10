from __future__ import annotations
import ulid
from typing import Optional, List
from app.schemas.types import DNSArtifactV1, HTTPRequestArtifactV1, TargetV1
from app.schemas.finding_v1 import FindingV1, FindingScoreV1, FindingTargetRefV1, FindingEvidenceRefV1
from app.core.signatures import match_takeover_signature, body_contains_marker

def _pick_best_http_artifact(http_artifacts: List[HTTPRequestArtifactV1], host: str) -> Optional[HTTPRequestArtifactV1]:
    host_l = host.lower().rstrip(".")
    for a in http_artifacts:
        a_host = (a.host or "").lower().rstrip(".")
        if a_host == host_l:
            return a
    return http_artifacts[0] if http_artifacts else None

def evaluate_pb4(
    dns: DNSArtifactV1, 
    target: TargetV1, 
    http_artifacts: List[HTTPRequestArtifactV1]
) -> Optional[FindingV1]:
    
    if dns.error or not dns.cname:
        return None

    # Safe CNAME handling
    cname_val = dns.cname
    if isinstance(cname_val, list):
        cname_val = str(cname_val[0]) if cname_val else ""
    else:
        cname_val = str(cname_val)

    sig = match_takeover_signature(cname_val)
    if not sig:
        return None 

    http_a = _pick_best_http_artifact(http_artifacts, dns.domain)
    if not http_a:
        return None

    status = http_a.status_code
    if status is None:
        return None
        
    body_content = http_a.response_analysis_snippet or ""
    
    if status not in sig.status_codes:
        return None
    if not body_contains_marker(body_content, sig.body_markers):
        return None

    evidence = [
        FindingEvidenceRefV1(evidence_id=f"ev_cname_{str(ulid.new())}", type="dns_cname", ref={"field": "cname"}, snippet=f"CNAME: {cname_val}"),
        FindingEvidenceRefV1(evidence_id=f"ev_http_{str(ulid.new())}", type="http_body_snippet", ref={"request_id": http_a.request_id}, snippet=f"HTTP {status} marker matched.")
    ]

    return FindingV1(
        finding_id=str(ulid.new()),
        playbook_id="PB4_SUBDOMAIN_TAKEOVER",
        title=f"Subdomain Takeover Suspected ({sig.service})",
        summary=f"The domain points to {sig.service} but resource seems unclaimed.",
        severity="critical",
        confidence="high",
        score=FindingScoreV1(total=9, threshold=1, model="risk_v1"),
        target=FindingTargetRefV1(
            target_id=target.target_id,
            input=target.input,
            canonical_url=target.canonical_url
        ),
        reasoning={"why_it_matters": "Attacker can hijack subdomain.", "analyst_notes": "Claim resource or delete CNAME."},
        signals=[],
        evidence=evidence,
        burp_artifacts={"urls": []}
    )