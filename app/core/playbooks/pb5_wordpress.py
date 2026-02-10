from __future__ import annotations
import ulid
import re
from urllib.parse import urlparse
from typing import Optional, List, Dict, Tuple, Any
import packaging.version

from app.schemas.types import CMSArtifactV1, HTTPRequestArtifactV1, TargetV1
from app.schemas.finding_v1 import FindingV1, FindingScoreV1, FindingTargetRefV1, FindingEvidenceRefV1

def _get_header(headers: Dict[str, str], key: str) -> str:
    if not headers:
        return ""
    key_lower = str(key).lower()
    for k, v in headers.items():
        if k.lower() == key_lower:
            return str(v)
    return ""

def _get_url(a: HTTPRequestArtifactV1) -> str:
    return a.effective_url or a.url or ""

def _normalize_path(url: str) -> str:
    try:
        return urlparse(url).path.lower().rstrip("/")
    except Exception:
        return ""

def _find_artifact_by_path(artifacts: List[HTTPRequestArtifactV1], path_suffix: str) -> Optional[HTTPRequestArtifactV1]:
    candidates = []
    target_path = path_suffix.lower()
    for a in artifacts:
        url = _get_url(a)
        a_path = _normalize_path(url)
        if a_path.endswith(target_path):
            candidates.append(a)
            
    if not candidates:
        return None
        
    # Tri par status 200 puis par présence de contenu
    candidates.sort(key=lambda x: (x.status_code == 200, len(x.response_analysis_snippet or "") > 0), reverse=True)
    return candidates[0]

def _extract_wp_version(artifacts: List[HTTPRequestArtifactV1]) -> Optional[Tuple[str, str, str]]:
    readme = _find_artifact_by_path(artifacts, "/readme.html")
    if readme and readme.status_code in (200, 301, 302):
        snippet = readme.response_analysis_snippet or ""
        match = re.search(r"Version\s+([0-9]+\.[0-9]+(\.[0-9]+)?)", snippet, re.IGNORECASE)
        if match:
            return match.group(1), "readme.html", "high"
    
    for a in artifacts:
        ctype = _get_header(a.headers, "content-type")
        if a.response_analysis_snippet and "html" in ctype.lower():
            match = re.search(r'content="WordPress\s+([0-9]+\.[0-9]+(\.[0-9]+)?)"', a.response_analysis_snippet, re.IGNORECASE)
            if match:
                return match.group(1), f"meta-generator ({_normalize_path(_get_url(a))})", "medium"
    return None

def evaluate_pb5(
    cms: CMSArtifactV1, 
    target: TargetV1, 
    http_artifacts: List[HTTPRequestArtifactV1],
    cve_db: List[Dict[str, Any]] = [] # CORRECTION : Ajout du paramètre cve_db
) -> List[FindingV1]:
    
    findings = []
    if not cms or cms.detected_cms != "wordpress" or cms.confidence == "low":
        return []

    # 1. User Enumeration
    users_endpoint = _find_artifact_by_path(http_artifacts, "/wp-json/wp/v2/users")
    if users_endpoint and users_endpoint.status_code == 200:
        snippet = users_endpoint.response_analysis_snippet or ""
        if "id" in snippet and "slug" in snippet:
            evidence = [FindingEvidenceRefV1(
                evidence_id=f"ev_users_{str(ulid.new())}", 
                type="http_body_snippet", 
                ref={"request_id": users_endpoint.request_id}, 
                snippet=f"REST API exposes users. Estimate: {snippet.count('id')//2}."
            )]
            findings.append(FindingV1(
                finding_id=str(ulid.new()), playbook_id="PB5_WP_USER_ENUM",
                title="WordPress User Enumeration Exposed",
                summary="The REST API endpoint /wp-json/wp/v2/users is publicly accessible.",
                severity="medium", confidence="high",
                score=FindingScoreV1(total=5, threshold=1, model="risk_v1"),
                target=FindingTargetRefV1(target_id=target.target_id, input=target.input, canonical_url=target.canonical_url),
                reasoning={"why_it_matters": "Attackers can scrape usernames.", "analyst_notes": "Disable user enumeration."},
                evidence=evidence, burp_artifacts={"urls": []}
            ))

    # 2. XML-RPC
    xmlrpc = _find_artifact_by_path(http_artifacts, "/xmlrpc.php")
    if xmlrpc and xmlrpc.status_code == 405: # Method Not Allowed = Often active but needs POST
        evidence = [FindingEvidenceRefV1(
            evidence_id=f"ev_xmlrpc_{str(ulid.new())}", 
            type="http_status", 
            ref={"request_id": xmlrpc.request_id}, 
            snippet="XML-RPC endpoint exists (405 Method Not Allowed)."
        )]
        findings.append(FindingV1(
            finding_id=str(ulid.new()), playbook_id="PB5_WP_XMLRPC_ENABLED",
            title="WordPress XML-RPC Interface Enabled",
            summary="xmlrpc.php is accessible and may allow brute-force attacks.",
            severity="low", confidence="medium",
            score=FindingScoreV1(total=3, threshold=1, model="risk_v1"),
            target=FindingTargetRefV1(target_id=target.target_id, input=target.input, canonical_url=target.canonical_url),
            reasoning={"why_it_matters": "DDoS/Brute-force amplification.", "analyst_notes": "Block access to xmlrpc.php."},
            evidence=evidence, burp_artifacts={"urls": []}
        ))

    # 3. Version & CVEs
    version_info = _extract_wp_version(http_artifacts)
    if version_info:
        version_str, source, conf = version_info
        
        # Version Disclosure Finding
        evidence_ver = [FindingEvidenceRefV1(
            evidence_id=f"ev_ver_{str(ulid.new())}", 
            type="version_string", 
            ref={"source": source}, 
            snippet=f"Detected Version: {version_str}"
        )]
        findings.append(FindingV1(
            finding_id=str(ulid.new()), playbook_id="PB5_WP_VERSION_DISCLOSURE", 
            title=f"WordPress Version Disclosed ({version_str})", 
            summary=f"Version {version_str} visible via {source}.", 
            severity="low", confidence=conf, 
            score=FindingScoreV1(total=2, threshold=1, model="risk_v1"),
            target=FindingTargetRefV1(target_id=target.target_id, input=target.input, canonical_url=target.canonical_url),
            reasoning={"why_it_matters": "Maps vulnerabilities.", "analyst_notes": "Hide version."}, 
            evidence=evidence_ver, burp_artifacts={"urls": []}
        ))

        # CVE Check Logic
        try:
            detected_ver = packaging.version.parse(version_str)
            for cve in cve_db:
                aff = cve.get("affected_versions", {})
                op = aff.get("operator")
                limit_ver_str = aff.get("version")
                
                match = False
                if op == "<" and limit_ver_str:
                    limit_ver = packaging.version.parse(limit_ver_str)
                    if detected_ver < limit_ver:
                        match = True
                
                if match:
                    findings.append(FindingV1(
                        finding_id=str(ulid.new()), 
                        playbook_id=f"PB5_WP_CVE_{cve['id'].replace('-', '_')}",
                        title=f"{cve['id']}: {cve['title']}",
                        summary=f"WordPress {version_str} is vulnerable to {cve['id']}. {cve['description']}",
                        severity=cve.get("severity", "high"), # type: ignore
                        confidence="high",
                        score=FindingScoreV1(total=9, threshold=1, model="risk_v1"),
                        target=FindingTargetRefV1(target_id=target.target_id, input=target.input, canonical_url=target.canonical_url),
                        reasoning={"why_it_matters": "Known exploit exists.", "analyst_notes": "Upgrade WordPress immediately."},
                        evidence=evidence_ver, 
                        burp_artifacts={"urls": []}
                    ))
        except Exception:
            pass

    return findings