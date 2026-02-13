from __future__ import annotations

import time
from typing import Any, Dict, List

import ulid

from app.schemas.types import CMSArtifactV1, HTTPRequestArtifactV1, TargetV1, TimingsMs


def detect_cms(
    target: TargetV1, http_artifacts: List[HTTPRequestArtifactV1], rules: List[Dict[str, Any]]
) -> CMSArtifactV1:
    t0 = time.perf_counter()

    results: dict[str, int] = {}

    for a in http_artifacts:
        for rule in rules:
            if not isinstance(rule, dict) or "name" not in rule:
                continue

            name = str(rule["name"])
            indicators = rule.get("indicators", [])
            if not isinstance(indicators, list):
                continue

            matched = False
            for ind in indicators:
                if not isinstance(ind, dict):
                    continue
                itype = ind.get("type")
                icontent = ind.get("content", "")

                if itype == "body" and icontent in (a.response_analysis_snippet or ""):
                    matched = True
                    break
                if itype == "header":
                    # Correction B007 : Utilisation de '_' pour la variable h_name non utilisée
                    for _, h_val in a.headers.items():
                        if icontent.lower() in h_val.lower():
                            matched = True
                            break
                if matched:
                    break

            if matched:
                results[name] = results.get(name, 0) + 1

    cms_name = "unknown"
    confidence = "low"

    if results:
        # Utilisation d'une lambda explicite pour MyPy
        best_cms = max(results, key=lambda k: results[k])
        count = results[best_cms]
        cms_name = best_cms
        confidence = "high" if count >= 1 else "medium"

    duration = int((time.perf_counter() - t0) * 1000)

    return CMSArtifactV1(
        cms_id=str(ulid.new()),
        target_id=target.target_id,
        detected_cms=cms_name,
        confidence=confidence,
        timings_ms=TimingsMs(total=duration),
    )
