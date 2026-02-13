from __future__ import annotations

from typing import Optional

import ulid

from app.schemas.finding_v1 import EvidenceV1, FindingScoreV1, FindingTargetRefV1, FindingV1
from app.schemas.types import DNSArtifactV1, Severity, TargetV1


def evaluate_pb3(dns: DNSArtifactV1, target: TargetV1) -> Optional[FindingV1]:
    """
    PB3: Analyse de l'authentification Email (SPF/DMARC).
    """
    if dns.error:
        return None

    spf_present = any("v=spf1" in txt.lower() for txt in dns.txt)
    dmarc_present = any("v=dmarc1" in txt.lower() for txt in dns.dmarc)

    if spf_present and dmarc_present:
        return None

    severity_val: Severity = "info"
    title = "Email Authentication Weakness"
    summary = ""
    score_val = 1

    if not spf_present and not dmarc_present:
        title = "Email Spoofing Risk: SPF and DMARC Missing"
        summary = "Domain is completely unprotected against email spoofing."
        severity_val = "critical"
        score_val = 9
    elif not dmarc_present:
        title = "Email Spoofing Risk: DMARC Missing"
        summary = "No DMARC record found, allowing potential unauthorized use."
        severity_val = "high"
        score_val = 7
    elif not spf_present:
        title = "Email Spoofing Risk: SPF Missing"
        summary = "SPF record is missing."
        severity_val = "medium"
        score_val = 5

    is_partial = any(w.startswith("TXT@") or "_dmarc" in w for w in dns.warnings)
    if (dns.registrable_domain_method == "naive" or is_partial) and severity_val in (
        "critical",
        "high",
    ):
        severity_val = "medium"
        summary += " (Risk degraded due to partial or naive DNS data)."

    evidence_list = [
        EvidenceV1(
            evidence_id=f"ev_dns_{ulid.new()}",
            type="dns_record_check",
            snippet=f"Domain checked: {dns.domain_checked_for_email_auth or dns.domain}",
            ref={"spf": spf_present, "dmarc": dmarc_present, "warnings": dns.warnings},
        )
    ]

    return FindingV1(
        finding_id=str(ulid.new()),
        playbook_id="PB3_EMAIL_AUTH",
        title=title,
        summary=summary,
        severity=severity_val,
        confidence="high" if not is_partial else "medium",
        score=FindingScoreV1(total=score_val, threshold=1, model="risk_v1"),
        target=FindingTargetRefV1(
            target_id=target.target_id, input=target.input, canonical_url=target.canonical_url
        ),
        reasoning={
            "why_it_matters": "Email spoofing is a common vector for phishing.",
            "analyst_notes": "Results based on registrable domain check.",
        },
        evidence=evidence_list,
    )
