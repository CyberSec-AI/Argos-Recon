from __future__ import annotations
import time
import ulid
from typing import List, Dict
from app.schemas.types import CMSArtifactV1, HTTPRequestArtifactV1

def detect_cms(target: dict, http_artifacts: List[HTTPRequestArtifactV1]) -> CMSArtifactV1:
    """
    Analyse les artefacts HTTP (baseline + probes) pour détecter un CMS.
    Heuristique low-noise, basée sur snippets + headers + endpoints.
    """
    t0 = time.perf_counter()

    artifact = CMSArtifactV1(
        cms_id=str(ulid.new()),
        target_id=target["target_id"],
        detected_cms="unknown",
        confidence="low",
    )

    evidence_set: set[str] = set()
    scores: Dict[str, int] = {"wordpress": 0, "joomla": 0, "drupal": 0}

    for req in http_artifacts:
        body = (req.response_analysis_snippet or "").lower()
        headers = {k.lower(): (v or "").lower() for k, v in (req.headers or {}).items()}
        url = (req.url or "").lower()
        status = req.status_code

        # ---- WORDPRESS ----
        # Strong indicators (+3)
        if "/wp-login.php" in url and status in (200, 302):
            if ("wp-submit" in body) or ("user_login" in body) or ('name="log"' in body):
                scores["wordpress"] += 3
                evidence_set.add(f"Endpoint: WP login detected at {req.url}")

        if "/wp-json/" in url and status == 200:
            if ("namespaces" in body) or ("namespace" in body):
                scores["wordpress"] += 3
                evidence_set.add(f"Endpoint: WP REST API detected at {req.url}")

        if 'content="wordpress' in body:
            scores["wordpress"] += 3
            evidence_set.add("Meta Generator: WordPress detected in HTML body")

        # Medium indicators (+1)
        if "/wp-content/" in body:
            scores["wordpress"] += 1
            evidence_set.add("Structure: Found '/wp-content/' reference in body")

        if "/wp-includes/" in body:
            scores["wordpress"] += 1
            evidence_set.add("Structure: Found '/wp-includes/' reference in body")

        # ---- JOOMLA ----
        if 'content="joomla' in body:
            scores["joomla"] += 3
            evidence_set.add("Meta Generator: Joomla detected")

        if "/media/system/js/" in body:
            scores["joomla"] += 1
            evidence_set.add("Structure: Found Joomla media path")

        if "/administrator/" in url and status in (200, 302) and "joomla" in body:
            scores["joomla"] += 3
            evidence_set.add("Endpoint: Joomla Administrator panel found")

        # ---- DRUPAL ----
        # Correction précédence + robustesse header
        if ('content="drupal' in body) or (("x-generator" in headers) and ("drupal" in headers["x-generator"])):
            scores["drupal"] += 3
            evidence_set.add("Meta/Header: Drupal detected")

        if "/sites/default/files" in body:
            scores["drupal"] += 1
            evidence_set.add("Structure: Found Drupal files path")

    best_cms = max(scores, key=scores.get)
    best_score = scores[best_cms]

    if best_score >= 3:
        artifact.detected_cms = best_cms # type: ignore
        artifact.confidence = "high"
    elif best_score >= 1:
        artifact.detected_cms = best_cms # type: ignore
        artifact.confidence = "medium"
    else:
        artifact.detected_cms = "unknown"
        artifact.confidence = "low"

    artifact.evidence = sorted(evidence_set)
    artifact.timings_ms = int((time.perf_counter() - t0) * 1000)
    return artifact