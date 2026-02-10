from __future__ import annotations
import ulid
import re
from urllib.parse import urlparse
from typing import Optional, List, Dict, Any, Tuple

from app.schemas.types import CMSArtifactV1, HTTPRequestArtifactV1
from app.schemas.finding_v1 import FindingV1, FindingScoreV1, FindingTargetRefV1, FindingEvidenceRefV1

# --- HELPERS ROBUSTES ---

def _get_header(headers: Dict[str, str], key: str) -> str:
    """Récupère un header de façon case-insensitive et type-safe."""
    if not headers:
        return ""
    key_lower = str(key).lower()
    for k, v in headers.items():
        if str(k).lower() == key_lower:
            return str(v)
    return ""

def _get_url(req: HTTPRequestArtifactV1) -> str:
    """Privilégie l'URL effective (post-redirection) sinon l'URL demandée."""
    return req.effective_url if req.effective_url else req.url

def _normalize_path(url: str) -> str:
    """Extrait le chemin normalisé d'une URL (sans query params)."""
    try:
        return urlparse(url).path.lower().rstrip("/")
    except Exception:
        return ""

def _find_artifact_by_path(artifacts: List[HTTPRequestArtifactV1], path_suffix: str) -> Optional[HTTPRequestArtifactV1]:
    """
    Retrouve la 'meilleure' requête dont le chemin se termine par path_suffix.
    Priorité : Status 200 > Snippet présent > Plus récent.
    """
    target_path = path_suffix.lower().rstrip("/")
    candidates = []
    
    for a in artifacts:
        url = _get_url(a)
        a_path = _normalize_path(url)
        if a_path.endswith(target_path):
            candidates.append(a)
            
    if not candidates:
        return None
        
    # Tri intelligent :
    # 1. Status 200 (True > False)
    # 2. Snippet non vide (len > 0)
    candidates.sort(key=lambda x: (
        x.status_code == 200, 
        len(x.response_analysis_snippet or "") > 0
    ), reverse=True)
    
    return candidates[0]

def _extract_wp_version(artifacts: List[HTTPRequestArtifactV1]) -> Optional[Tuple[str, str, str]]:
    """Retourne (version, source, confiance)."""
    # 1. Readme (High)
    readme = _find_artifact_by_path(artifacts, "/readme.html")
    if readme and readme.status_code in (200, 301, 302):
        snippet = readme.response_analysis_snippet or ""
        match = re.search(r"Version\s+([0-9]+\.[0-9]+(\.[0-9]+)?)", snippet, re.IGNORECASE)
        if match:
            return match.group(1), "readme.html", "high"

    # 2. Meta Generator (Medium)
    for a in artifacts:
        ctype = _get_header(a.headers, "content-type")
        if a.response_analysis_snippet and "html" in ctype.lower():
            match = re.search(r'content="WordPress\s+([0-9]+\.[0-9]+(\.[0-9]+)?)"', a.response_analysis_snippet, re.IGNORECASE)
            if match:
                return match.group(1), f"meta-generator ({_normalize_path(_get_url(a))})", "medium"
    return None

# --- LOGIQUE PRINCIPALE ---

def evaluate_pb5(
    cms: CMSArtifactV1, 
    target: dict, 
    http_artifacts: List[HTTPRequestArtifactV1]
) -> List[FindingV1]:
    
    findings = []
    
    # 🎯 GATEKEEPER : WordPress confirmé uniquement (Confiance Medium/High)
    if not cms or cms.detected_cms != "wordpress" or cms.confidence == "low":
        return []

    # --- PB5-A : User Enumeration ---
    users_req = _find_artifact_by_path(http_artifacts, "/wp-json/wp/v2/users")
    
    if users_req:
        if users_req.status_code == 200:
            ctype = _get_header(users_req.headers, "content-type").lower()
            if "json" in ctype:
                body = users_req.response_analysis_snippet or ""
                # Regex robuste pour détecter des clés JSON utilisateurs
                has_user_keys = re.search(r'"(id|slug|name|username)"\s*:', body)
                starts_list = body.strip().startswith("[")

                if has_user_keys or starts_list:
                    user_count = body.count('"id":') or "unknown"
                    evidence = [FindingEvidenceRefV1(
                        evidence_id=f"ev_users_{str(ulid.new())}",
                        type="http_body_snippet",
                        ref={"artifact": "http", "request_id": users_req.request_id},
                        snippet=f"REST API exposes users. Estimate: {user_count}. Content-Type: {ctype}"
                    )]
                    
                    findings.append(FindingV1(
                        finding_id=str(ulid.new()),
                        playbook_id="PB5_WP_USER_ENUM",
                        title="WordPress User Enumeration Exposed",
                        summary="The REST API endpoint /wp-json/wp/v2/users is publicly accessible.",
                        severity="medium", 
                        confidence="high",
                        score=FindingScoreV1(total=5, threshold=1, model="risk_v1"),
                        target=FindingTargetRefV1(target_id=target["target_id"], input=target["input"], canonical_url=target["canonical_url"]),
                        reasoning={"why_it_matters": "Attackers can scrape usernames for brute-force.", "analyst_notes": "Disable user enumeration."},
                        evidence=evidence,
                        burp_artifacts={"urls": [_get_url(users_req)]}
                    ))
        elif users_req.status_code in (401, 403):
            # Info silencieuse : endpoint existe mais protégé
            cms.evidence.append(f"Info: User enumeration endpoint found but protected ({users_req.status_code}).")

    # --- PB5-B : XML-RPC Exposure ---
    xml_req = _find_artifact_by_path(http_artifacts, "/xmlrpc.php")
    
    # Low-Noise Strict : 200 OK + Marker obligatoire
    if xml_req and xml_req.status_code == 200:
        body = xml_req.response_analysis_snippet or ""
        if "XML-RPC server accepts POST requests only" in body:
            evidence = [FindingEvidenceRefV1(
                evidence_id=f"ev_xmlrpc_{str(ulid.new())}",
                type="http_body_snippet",
                ref={"artifact": "http", "request_id": xml_req.request_id},
                snippet="XML-RPC active. Marker found."
            )]
            
            findings.append(FindingV1(
                finding_id=str(ulid.new()),
                playbook_id="PB5_WP_XMLRPC_EXPOSED",
                title="WordPress XML-RPC Interface Exposed",
                summary="xmlrpc.php is enabled and accessible.",
                severity="medium",
                confidence="high",
                score=FindingScoreV1(total=5, threshold=1, model="risk_v1"),
                target=FindingTargetRefV1(target_id=target["target_id"], input=target["input"], canonical_url=target["canonical_url"]),
                reasoning={"why_it_matters": "Vector for DDoS amplification and brute-force.", "analyst_notes": "Block access to xmlrpc.php."},
                evidence=evidence,
                burp_artifacts={"urls": [_get_url(xml_req)]}
            ))
    elif xml_req and xml_req.status_code in (403, 405):
         cms.evidence.append(f"Info: XML-RPC endpoint present but restricted ({xml_req.status_code}).")

    # --- PB5-C : Version Disclosure ---
    version_info = _extract_wp_version(http_artifacts)
    if version_info:
        version, source, conf = version_info
        evidence = [FindingEvidenceRefV1(
            evidence_id=f"ev_ver_{str(ulid.new())}",
            type="version_string",
            ref={"source": source},
            snippet=f"Detected Version: {version}"
        )]
        
        findings.append(FindingV1(
            finding_id=str(ulid.new()),
            playbook_id="PB5_WP_VERSION_DISCLOSURE",
            title=f"WordPress Version Disclosed ({version})",
            summary=f"The WordPress version {version} is publicly visible via {source}.",
            severity="low", 
            confidence=conf,
            score=FindingScoreV1(total=2, threshold=1, model="risk_v1"),
            target=FindingTargetRefV1(target_id=target["target_id"], input=target["input"], canonical_url=target["canonical_url"]),
            reasoning={"why_it_matters": "Helps attackers map known vulnerabilities.", "analyst_notes": "Hide version meta tags."},
            evidence=evidence,
            burp_artifacts={"urls": []}
        ))

    # --- PB5-D : CORRELATION ---
    found_ids_map = {f.playbook_id: f.finding_id for f in findings}
    
    if "PB5_WP_USER_ENUM" in found_ids_map and "PB5_WP_XMLRPC_EXPOSED" in found_ids_map:
        # Lien vers les preuves existantes
        correlation_evidence = [
            FindingEvidenceRefV1(
                evidence_id=f"ev_corr_{str(ulid.new())}",
                type="correlation_link",
                ref={"related_finding_ids": [found_ids_map["PB5_WP_USER_ENUM"], found_ids_map["PB5_WP_XMLRPC_EXPOSED"]]},
                snippet="Correlation: Valid Usernames (Enum) + Brute-Force Interface (XML-RPC) = High Risk."
            )
        ]

        findings.append(FindingV1(
            finding_id=str(ulid.new()),
            playbook_id="PB5_WP_HIGH_RISK_COMBINATION",
            title="High Risk: WordPress Brute-Force Attack Surface",
            summary="Combined exposure of User Enumeration and XML-RPC allows highly efficient brute-force attacks.",
            severity="high",
            confidence="high",
            score=FindingScoreV1(total=8, threshold=1, model="risk_v1"),
            target=FindingTargetRefV1(target_id=target["target_id"], input=target["input"], canonical_url=target["canonical_url"]),
            reasoning={
                "why_it_matters": "Attackers have valid usernames and a fast login interface.", 
                "analyst_notes": "Immediate Action: Block XML-RPC and disable REST API user endpoints."
            },
            evidence=correlation_evidence,
            burp_artifacts={"urls": []}
        ))

    return findings