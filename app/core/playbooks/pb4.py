from __future__ import annotations
import ulid
from typing import Optional, List

from app.schemas.types import DNSArtifactV1, HTTPRequestArtifactV1
from app.schemas.finding_v1 import FindingV1, FindingScoreV1, FindingTargetRefV1, FindingEvidenceRefV1
from app.core.signatures import match_takeover_signature, body_contains_marker

def _pick_best_http_artifact(http_artifacts: List[HTTPRequestArtifactV1], host: str) -> Optional[HTTPRequestArtifactV1]:
    # Normalisation du host cible
    host_l = host.lower().rstrip(".")
    
    for a in http_artifacts:
        # On compare avec le host de chaque requête normalisé
        a_host = (a.host or "").lower().rstrip(".")
        if a_host == host_l:
            return a
            
    # Fallback : on prend le premier artefact disponible (souvent la baseline)
    return http_artifacts[0] if http_artifacts else None

def evaluate_pb4(
    dns: DNSArtifactV1,
    target: dict,
    http_artifacts: List[HTTPRequestArtifactV1],
) -> Optional[FindingV1]:
    
    # 1. Pré-requis DNS (On évite l'analyse si le DNS a échoué)
    if dns.error:
        return None
    if not dns.cname:
        return None

    # 2. Matching CNAME (Signature Stricte)
    sig = match_takeover_signature(dns.cname)
    if not sig:
        return None 

    # 3. Validation HTTP (Confirmation de l'abandon)
    http_a = _pick_best_http_artifact(http_artifacts, dns.domain)
    if not http_a:
        return None

    status = http_a.status_code
    # Protection : Si la requête HTTP a échoué (timeout, reset), pas de status
    if status is None:
        return None
        
    body_content = http_a.response_analysis_snippet or ""
    
    # Check Status Code
    if status not in sig.status_codes:
        return None
        
    # Check Body Markers
    if not body_contains_marker(body_content, sig.body_markers):
        return None

    # 4. Construction de la Preuve
    evidence = [
        FindingEvidenceRefV1(
            evidence_id=f"ev_cname_{str(ulid.new())}",
            type="dns_cname",
            ref={"artifact": "dns", "field": "cname"},
            snippet=f"Dangling CNAME detected: {dns.cname} (Service: {sig.service})",
        ),
        FindingEvidenceRefV1(
            evidence_id=f"ev_http_{str(ulid.new())}",
            type="http_body_snippet",
            ref={"artifact": "http", "field": "response_analysis_snippet", "request_id": http_a.request_id},
            snippet=f"HTTP {status} response matches abandonment signature: {body_content[:200]}...",
        ),
    ]

    return FindingV1(
        finding_id=str(ulid.new()),
        playbook_id="PB4_SUBDOMAIN_TAKEOVER",
        title=f"Subdomain Takeover Suspected ({sig.service})",
        summary=f"The domain points to {sig.service} via CNAME, but the resource appears unclaimed.",
        severity="critical",
        confidence="high",
        score=FindingScoreV1(total=9, threshold=1, model="risk_v1"),
        target=FindingTargetRefV1(
            target_id=target["target_id"],
            input=target["input"],
            canonical_url=target["canonical_url"],
        ),
        reasoning={
            "why_it_matters": "An attacker can register the unclaimed resource at the provider and hijack the subdomain to serve malicious content.",
            "analyst_notes": f"Verify ownership on the {sig.service} console immediately. If the resource is unused, delete the DNS CNAME record.",
        },
        signals=[],
        evidence=evidence,
        burp_artifacts={"urls": []}, # Requis par le validateur Pydantic
    )