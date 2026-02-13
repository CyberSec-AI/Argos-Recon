from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

import ulid

from app.schemas.types import CMSArtifactV1, Confidence, HTTPRequestArtifactV1, TargetV1, TimingsMs


def detect_cms(
    target: TargetV1,
    http_artifacts: List[HTTPRequestArtifactV1],
    rules: Optional[List[Dict[str, Any]]] = None,
) -> CMSArtifactV1:
    t0 = time.perf_counter()
    matched_heuristics = set()
    WP_LOGIN_CODES = {200, 301, 302, 401, 403}

    for a in http_artifacts:
        if a.error or a.status_code is None:
            continue

        h_lc = a.headers
        body_lc = (a.response_analysis_snippet or "").lower()
        url_lc = a.url.lower()

        if "link" in h_lc and "wp-json" in h_lc["link"]:
            matched_heuristics.add("wp_json_link")
        if "wp-login.php" in url_lc and a.status_code in WP_LOGIN_CODES:
            matched_heuristics.add("wp_login")
        if "xmlrpc.php" in url_lc and a.status_code in {200, 405, 403}:
            matched_heuristics.add("wp_xmlrpc")
        if any(x in body_lc for x in ["wp-content", "wp-includes"]):
            matched_heuristics.add("wp_assets")

    weights = {"wp_json_link": 0.6, "wp_login": 0.5, "wp_xmlrpc": 0.4, "wp_assets": 0.4}
    score = sum(weights[h] for h in matched_heuristics)

    cms_name = "unknown"
    confidence: Confidence = "low"

    if score >= 0.8:
        cms_name, confidence = "wordpress", "high"
    elif score >= 0.4:
        cms_name, confidence = "wordpress", "medium"

    duration = int((time.perf_counter() - t0) * 1000)

    return CMSArtifactV1(
        cms_id=str(ulid.new()),
        target_id=target.target_id,
        detected_cms=cms_name,
        confidence=confidence,
        timings_ms=TimingsMs(total=duration),
    )
