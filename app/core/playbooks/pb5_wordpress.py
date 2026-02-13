from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import packaging.version
import ulid

from app.schemas.finding_v1 import (
    FindingEvidenceRefV1,
    FindingScoreV1,
    FindingTargetRefV1,
    FindingV1,
)
from app.schemas.types import CMSArtifactV1, HTTPRequestArtifactV1, TargetV1


def _get_header(headers: Dict[str, str], key: str) -> str:
    """Récupère un header de manière insensible à la casse."""
    if not headers:
        return ""
    key_lower = str(key).lower()
    for k, v in headers.items():
        if k.lower() == key_lower:
            return str(v)
    return ""


def _get_url(a: HTTPRequestArtifactV1) -> str:
    """Récupère l'URL effective ou originale de l'artefact."""
    return a.effective_url or a.url or ""


def _normalize_path(url: str) -> str:
    """Extrait le chemin normalisé d'une URL."""
    try:
        return urlparse(url).path.lower().rstrip("/")
    except Exception:
        return ""


def _find_artifact_by_path(
    artifacts: List[HTTPRequestArtifactV1], path_suffix: str
) -> Optional[HTTPRequestArtifactV1]:
    """Trouve le meilleur artefact correspondant à une fin de chemin spécifique."""
    candidates = []
    target_path = path_suffix.lower()
    for a in artifacts:
        url = _get_url(a)
        a_path = _normalize_path(url)
        if a_path.endswith(target_path):
            candidates.append(a)

    if not candidates:
        return None

    # Tri par code 200 en priorité, puis par longueur de snippet
    candidates.sort(
        key=lambda x: (x.status_code == 200, len(x.response_analysis_snippet or "") > 0),
        reverse=True,
    )
    return candidates[0]


def _extract_wp_version(
    artifacts: List[HTTPRequestArtifactV1],
) -> Optional[Tuple[str, str, str]]:
    """Tente d'extraire la version de WordPress via différentes sources."""
    # Source A: readme.html
    readme = _find_artifact_by_path(artifacts, "/readme.html")
    if readme and readme.status_code in (200, 301, 302):
        snippet = readme.response_analysis_snippet or ""
        match = re.search(r"Version\s+([0-9]+\.[0-9]+(\.[0-9]+)?)", snippet, re.IGNORECASE)
        if match:
            return match.group(1), "readme.html", "high"

    # Source B: Meta generator dans le HTML
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
    cms: CMSArtifactV1,
    target: TargetV1,
    http_artifacts: List[HTTPRequestArtifactV1],
    cve_db: Optional[List[Dict[str, Any]]] = None,
) -> List[FindingV1]:
    """
    Analyse les vulnérabilités et configurations spécifiques à WordPress.
    """
    # Fix B006: Initialisation sécurisée de l'argument par défaut
    if cve_db is None:
        cve_db = []

    findings: List[FindingV1] = []

    if not cms or cms.detected_cms != "wordpress" or cms.confidence == "low":
        return []

    # 1. Détection de l'énumération des utilisateurs (REST API)
    users_endpoint = _find_artifact_by_path(http_artifacts, "/wp-json/wp/v2/users")
    if users_endpoint and users_endpoint.status_code == 200:
        snippet = users_endpoint.response_analysis_snippet or ""
        if "id" in snippet and "slug" in snippet:
            count = snippet.count('"id"')
            evidence = [
                FindingEvidenceRefV1(
                    evidence_id=f"ev_users_{str(ulid.new())}",
                    type="http_body_snippet",
                    ref={"request_id": users_endpoint.request_id},
                    snippet=f"REST API exposes users. Estimate: {count}.",
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
                        "why_it_matters": "Attackers can scrape usernames to build wordlists.",
                        "analyst_notes": "Disable user enumeration in WP-JSON settings.",
                    },
                    evidence=evidence,
                )
            )

    # 2. Vérification XML-RPC
    xmlrpc = _find_artifact_by_path(http_artifacts, "/xmlrpc.php")
    if xmlrpc and xmlrpc.status_code in (200, 405):
        evidence = [
            FindingEvidenceRefV1(
                evidence_id=f"ev_xmlrpc_{str(ulid.new())}",
                type="http_status",
                ref={"request_id": xmlrpc.request_id},
                snippet=f"XML-RPC endpoint exists (Status: {xmlrpc.status_code}).",
            )
        ]
        findings.append(
            FindingV1(
                finding_id=str(ulid.new()),
                playbook_id="PB5_WP_XMLRPC_ENABLED",
                title="WordPress XML-RPC Interface Enabled",
                summary="xmlrpc.php is accessible and may allow brute-force attacks.",
                severity="low",
                confidence="medium",
                score=FindingScoreV1(total=3, threshold=1, model="risk_v1"),
                target=FindingTargetRefV1(
                    target_id=target.target_id,
                    input=target.input,
                    canonical_url=target.canonical_url,
                ),
                reasoning={
                    "why_it_matters": "DDoS and Brute-force amplification risk.",
                    "analyst_notes": "Restrict access to xmlrpc.php or disable it entirely.",
                },
                evidence=evidence,
            )
        )

    # 3. Analyse de version et corrélation CVE
    version_info = _extract_wp_version(http_artifacts)
    if version_info:
        version_str, source, conf = version_info

        # Signalement de la version
        evidence_ver = [
            FindingEvidenceRefV1(
                evidence_id=f"ev_ver_{str(ulid.new())}",
                type="version_string",
                ref={"source": source},
                snippet=f"Detected Version: {version_str}",
            )
        ]
        findings.append(
            FindingV1(
                finding_id=str(ulid.new()),
                playbook_id="PB5_WP_VERSION_DISCLOSURE",
                title=f"WordPress Version Disclosed ({version_str})",
                summary=f"Version {version_str} visible via {source}.",
                severity="low",
                confidence=conf,  # type: ignore
                score=FindingScoreV1(total=2, threshold=1, model="risk_v1"),
                target=FindingTargetRefV1(
                    target_id=target.target_id,
                    input=target.input,
                    canonical_url=target.canonical_url,
                ),
                reasoning={
                    "why_it_matters": "Aids attackers in mapping known vulnerabilities.",
                    "analyst_notes": "Hide version info via functions.php or plugins.",
                },
                evidence=evidence_ver,
            )
        )

        # Corrélation CVE
        if cve_db:
            try:
                detected_ver = packaging.version.parse(version_str)
                for cve in cve_db:
                    aff = cve.get("affected_versions", {})
                    op = aff.get("operator")
                    limit_ver_str = aff.get("version")

                    is_vulnerable = False
                    if op == "<" and limit_ver_str:
                        limit_ver = packaging.version.parse(limit_ver_str)
                        if detected_ver < limit_ver:
                            is_vulnerable = True

                    if is_vulnerable:
                        findings.append(
                            FindingV1(
                                finding_id=str(ulid.new()),
                                playbook_id=f"PB5_WP_CVE_{cve['id'].replace('-', '_')}",
                                title=f"{cve['id']}: {cve['title']}",
                                summary=f"WordPress {version_str} is vulnerable to {cve['id']}.",
                                severity=cve.get("severity", "high"),  # type: ignore
                                confidence="high",
                                score=FindingScoreV1(total=9, threshold=1, model="risk_v1"),
                                target=FindingTargetRefV1(
                                    target_id=target.target_id,
                                    input=target.input,
                                    canonical_url=target.canonical_url,
                                ),
                                reasoning={
                                    "why_it_matters": "Known exploits exist for this version.",
                                    "analyst_notes": "Urgent update required.",
                                },
                                evidence=evidence_ver,
                            )
                        )
            except Exception:
                pass

    return findings
