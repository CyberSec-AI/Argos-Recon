from __future__ import annotations
import ulid
from typing import Optional, List, Dict
from dataclasses import dataclass

from app.schemas.finding_v1 import FindingV1, FindingScoreV1, FindingTargetRefV1, FindingEvidenceRefV1
from app.schemas.types import DNSArtifactV1

@dataclass
class SPFAnalysis:
    present: bool
    record: Optional[str]
    all_mechanism: Optional[str]
    warning: Optional[str]

@dataclass
class DMARCAnalysis:
    present: bool
    record: Optional[str]
    tags: Dict[str, str]
    policy: Optional[str]
    warning: Optional[str]

def _pick_first_spf(records: List[str]) -> Optional[str]:
    for r in records:
        if r.strip().lower().startswith("v=spf1"):
            return r.strip()
    return None

def _pick_first_dmarc(records: List[str]) -> Optional[str]:
    for r in records:
        if r.strip().lower().startswith("v=dmarc1"):
            return r.strip()
    return None

def analyze_spf(root_txt: List[str]) -> SPFAnalysis:
    spf = _pick_first_spf(root_txt)
    if not spf:
        return SPFAnalysis(False, None, None, "No SPF record found on root TXT.")

    s = spf.lower()
    all_mech = None
    for mech in ("+all", "-all", "~all", "?all"):
        if mech in s.split():
            all_mech = mech
            break

    if all_mech == "+all":
        return SPFAnalysis(True, spf, all_mech, "SPF is overly permissive (+all).")
    if all_mech == "?all":
        return SPFAnalysis(True, spf, all_mech, "SPF is neutral (?all), offering no protection.")
    if all_mech == "~all":
        return SPFAnalysis(True, spf, all_mech, "SPF uses softfail (~all).")
    
    if not all_mech:
        return SPFAnalysis(True, spf, None, "SPF record found but no explicit all-mechanism detected (misconfigured).")

    return SPFAnalysis(True, spf, all_mech, None)

def parse_dmarc(record: str) -> Dict[str, str]:
    tags: Dict[str, str] = {}
    parts = record.split(";")
    for part in parts:
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        tags[k.strip().lower()] = v.strip()
    return tags

def analyze_dmarc(dmarc_txt: List[str]) -> DMARCAnalysis:
    rec = _pick_first_dmarc(dmarc_txt)
    if not rec:
        return DMARCAnalysis(False, None, {}, None, "No DMARC record found (_dmarc subdomain).")

    tags = parse_dmarc(rec)
    p = tags.get("p")
    warn = None

    if not p:
        warn = "DMARC record present but missing mandatory 'p=' policy."
    elif p.lower() == "none":
        warn = "DMARC policy is p=none (monitoring only)."

    return DMARCAnalysis(True, rec, tags, p.lower() if p else None, warn)

def evaluate_pb3(dns: DNSArtifactV1, target: dict) -> Optional[FindingV1]:
    # Sécurité anti-faux positifs
    if dns.error:
        return None

    spf = analyze_spf(dns.txt)
    dmarc = analyze_dmarc(dns.dmarc)

    severity = "info"
    title = ""
    desc = ""
    score_val = 0

    if not spf.present and not dmarc.present:
        severity = "critical"
        title = "Email Spoofing Risk: SPF and DMARC Missing"
        desc = "Domain is completely unprotected against email spoofing."
        score_val = 9
    elif not dmarc.present:
        severity = "high"
        title = "Email Spoofing Risk: DMARC Missing"
        desc = "No DMARC record found. Attackers can spoof emails even if SPF is present."
        score_val = 7
    elif dmarc.present and not dmarc.policy:
        severity = "high"
        title = "Email Security: DMARC Misconfigured (Missing Policy)"
        desc = "DMARC record exists but has no policy (p=), effectively invalid."
        score_val = 6
    elif spf.all_mechanism == "+all":
        severity = "high"
        title = "Email Security: SPF Permissive (+all)"
        desc = "SPF record allows any IP to send emails on behalf of this domain."
        score_val = 7
    elif dmarc.policy == "none":
        severity = "medium"
        title = "Email Security: DMARC Policy is None"
        desc = "DMARC is in monitoring mode (p=none) and does not block spoofed emails."
        score_val = 5
    elif spf.present and not spf.all_mechanism:
        severity = "medium"
        title = "Email Security: SPF Misconfigured (No 'all')"
        desc = "SPF record lacks a terminating mechanism (like -all or ~all)."
        score_val = 4
    elif spf.all_mechanism == "?all":
        severity = "medium"
        title = "Email Security: SPF Neutral (?all)"
        desc = "SPF record explicitly allows neutrality, offering weak protection."
        score_val = 4
    else:
        return None

    evidence_list = []
    
    evidence_list.append(FindingEvidenceRefV1(
        evidence_id=f"ev_spf_{str(ulid.new())}",
        type="dns_txt",
        ref={"artifact": "dns", "field": "txt"},
        snippet=f"SPF: {spf.record or 'Missing'} ({spf.warning or 'OK'})"
    ))
    
    evidence_list.append(FindingEvidenceRefV1(
        evidence_id=f"ev_dmarc_{str(ulid.new())}",
        type="dns_txt",
        ref={"artifact": "dns", "field": "dmarc"},
        snippet=f"DMARC: {dmarc.record or 'Missing'} ({dmarc.warning or 'OK'})"
    ))

    return FindingV1(
        finding_id=str(ulid.new()),
        playbook_id="PB3_EMAIL_AUTH",
        title=title,
        summary=desc,
        severity=severity,
        confidence="high",
        score=FindingScoreV1(total=score_val, threshold=1, model="risk_v1"),
        target=FindingTargetRefV1(
            target_id=target["target_id"],
            input=target["input"],
            canonical_url=target["canonical_url"]
        ),
        reasoning={
            "why_it_matters": "Without proper SPF/DMARC, attackers can spoof your domain for phishing.",
            "analyst_notes": "Implement strict DMARC (p=quarantine/reject) and restrictive SPF (-all)."
        },
        signals=[],
        evidence=evidence_list,
        # CORRECTION ICI : On passe un dict vide valide au lieu de None
        burp_artifacts={"urls": []}
    )