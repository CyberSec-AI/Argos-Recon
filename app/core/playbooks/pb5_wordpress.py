from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import ulid

from app.schemas.finding_v1 import (
    FindingEvidenceRefV1,
    FindingScoreV1,
    FindingTargetRefV1,
    FindingV1,
)
from app.schemas.types import CMSArtifactV1, HTTPRequestArtifactV1, TargetV1


def _get_header(headers: Dict[str, str], key: str) -> str:
    if not headers:
        return ""
    key_lower = str(key).lower()
    for k, v in headers.items():
        if str(k).lower() == key_lower:
            return str(v)
    return ""


def _get_url(req: HTTPRequestArtifactV1) -> str:
    return req.effective_url if req.effective_url else req.url


def _normalize_path(url: str) -> str:
    try:
        return urlparse(url).path.lower().rstrip("/")
    except Exception:
        return ""


def _find_artifact_by_path(
    artifacts: List[HTTPRequestArtifactV1], path_suffix: str
) -> Optional[HTTPRequestArtifactV1]:
    target_path = path_suffix.lower().rstrip("/")
    candidates = []
    for a in artifacts:
        url = _get_url(a)
        a_path = _normalize_path(url)
        if a_path.endswith(target_path):
            candidates.append(a)
    if not candidates:
        return None
    candidates.sort(
        key=lambda x: (
            x.status_code == 200,
            len(x.response_analysis_snippet or "") > 0,
        ),
        reverse=True,
    )
    return candidates[0]


def _extract_wp_version(
    artifacts: List[HTTPRequestArtifactV1],
) -> Optional[Tuple[str, str, str]]:
    readme = _find_artifact_by_path(artifacts, "/readme.html")
    if readme and readme.status_code in (200, 301, 302):
        snippet = readme.response_analysis_snippet or ""
        match = re.search(
            r"Version\s+([0-9]+\.[0-9]+(\.[0-9]+)?)", snippet, re.IGNORECASE
        )
        if match:
            return match.group(1), "readme.html", "high"
    for a in artifacts:
        ctype = _get_header(a.headers, "content-type")
        if a.response_analysis_snippet and "html" in ctype.lower():
            match = re.search(
                r'content="WordPress\s+([0-9]+\.[0-9]+(\.[0-9]+)?)"',
                a.response_analysis_snippet,
                re.IGNORECASE,
            )
            if match:
                return (
                    match.group(1),
                    f"meta-generator ({_normalize_path(_get_url(a))})",
                    "medium",
                )
    return None


def evaluate_pb5(
    cms: CMSArtifactV1, target: TargetV1, http_artifacts: List[HTTPRequestArtifactV1]
) -> List[FindingV1]:

    findings = []
    if not cms or cms.detected_cms != "wordpress" or cms.confidence == "low":
        return []

    users_req = _find_artifact_by_path(http_artifacts, "/wp-json/wp/v2/users")
    if users_req:
        if users_req.status_code == 200:
            ctype = _get_header(users_req.headers, "content-type").lower()
            if "json" in ctype:
                body = users_req.response_analysis_snippet or ""
                has_user_keys = re.search(r'"(id|slug|name|username)"\s*:', body)
                starts_list = body.strip().startswith("[")
                if has_user_keys or starts_list:
                    user_count = body.count('"id":') or "unknown"
                    evidence = [
                        FindingEvidenceRefV1(
                            evidence_id=f"ev_users_{str(ulid.new())}",
                            type="http_body_snippet",
                            ref={"request_id": users_req.request_id},
                            snippet=f"REST API exposes users. Estimate: {user_count}.",
                        )
                    ]
                    findings.append(
                        FindingV1(
                            finding_id=str(ulid.new()),
                            playbook_id="PB5_WP_USER_ENUM",
                            title="WordPress User Enumeration Exposed",
                            summary="The REST API endpoint /wp-json/wp/v2/users is publicly accessible.",
                            severity="medium",
                            confidence="high",
                            score=FindingScoreV1(total=5, threshold=1, model="risk_v1"),
                            target=FindingTargetRefV1(
                                target_id=target.target_id,
                                input=target.input,
                                canonical_url=target.canonical_url,
                            ),
                            reasoning={
                                "why_it_matters": "Attackers can scrape usernames.",
                                "analyst_notes": "Disable user enumeration.",
                            },
                            evidence=evidence,
                            burp_artifacts={"urls": []},
                        )
                    )
        elif users_req.status_code in (401, 403):
            cms.evidence.append(
                f"Info: User enumeration endpoint found but protected ({users_req.status_code})."
            )

    xml_req = _find_artifact_by_path(http_artifacts, "/xmlrpc.php")
    if xml_req and xml_req.status_code == 200:
        body = xml_req.response_analysis_snippet or ""
        if "XML-RPC server accepts POST requests only" in body:
            evidence = [
                FindingEvidenceRefV1(
                    evidence_id=f"ev_xmlrpc_{str(ulid.new())}",
                    type="http_body_snippet",
                    ref={"request_id": xml_req.request_id},
                    snippet="XML-RPC active. Marker found.",
                )
            ]
            findings.append(
                FindingV1(
                    finding_id=str(ulid.new()),
                    playbook_id="PB5_WP_XMLRPC_EXPOSED",
                    title="WordPress XML-RPC Interface Exposed",
                    summary="xmlrpc.php is enabled and accessible.",
                    severity="medium",
                    confidence="high",
                    score=FindingScoreV1(total=5, threshold=1, model="risk_v1"),
                    target=FindingTargetRefV1(
                        target_id=target.target_id,
                        input=target.input,
                        canonical_url=target.canonical_url,
                    ),
                    reasoning={
                        "why_it_matters": "Vector for DDoS/Brute-force.",
                        "analyst_notes": "Block xmlrpc.php.",
                    },
                    evidence=evidence,
                    burp_artifacts={"urls": []},
                )
            )

    version_info = _extract_wp_version(http_artifacts)
    if version_info:
        version, source, conf = version_info
        evidence = [
            FindingEvidenceRefV1(
                evidence_id=f"ev_ver_{str(ulid.new())}",
                type="version_string",
                ref={"source": source},
                snippet=f"Detected Version: {version}",
            )
        ]
        findings.append(
            FindingV1(
                finding_id=str(ulid.new()),
                playbook_id="PB5_WP_VERSION_DISCLOSURE",
                title=f"WordPress Version Disclosed ({version})",
                summary=f"Version {version} visible via {source}.",
                severity="low",
                confidence=conf,
                score=FindingScoreV1(total=2, threshold=1, model="risk_v1"),
                target=FindingTargetRefV1(
                    target_id=target.target_id,
                    input=target.input,
                    canonical_url=target.canonical_url,
                ),
                reasoning={
                    "why_it_matters": "Maps vulnerabilities.",
                    "analyst_notes": "Hide version.",
                },
                evidence=evidence,
                burp_artifacts={"urls": []},
            )
        )

    found_ids_map = {f.playbook_id: f.finding_id for f in findings}
    if "PB5_WP_USER_ENUM" in found_ids_map and "PB5_WP_XMLRPC_EXPOSED" in found_ids_map:
        correlation_evidence = [
            FindingEvidenceRefV1(
                evidence_id=f"ev_corr_{str(ulid.new())}",
                type="correlation_link",
                ref={
                    "related_finding_ids": [
                        found_ids_map["PB5_WP_USER_ENUM"],
                        found_ids_map["PB5_WP_XMLRPC_EXPOSED"],
                    ]
                },
                snippet="Correlation: Usernames + XML-RPC = High Risk.",
            )
        ]
        findings.append(
            FindingV1(
                finding_id=str(ulid.new()),
                playbook_id="PB5_WP_HIGH_RISK_COMBINATION",
                title="High Risk: WordPress Brute-Force Attack Surface",
                summary="Combined exposure allows efficient brute-force.",
                severity="high",
                confidence="high",
                score=FindingScoreV1(total=8, threshold=1, model="risk_v1"),
                target=FindingTargetRefV1(
                    target_id=target.target_id,
                    input=target.input,
                    canonical_url=target.canonical_url,
                ),
                reasoning={
                    "why_it_matters": "Valid usernames + fast login interface.",
                    "analyst_notes": "Block XML-RPC.",
                },
                evidence=correlation_evidence,
                burp_artifacts={"urls": []},
            )
        )

    return findings
