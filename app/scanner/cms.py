from __future__ import annotations
import time
import ulid
from typing import List, Dict, Any, Optional
from app.schemas.types import CMSArtifactV1, HTTPRequestArtifactV1, TargetV1

def detect_cms(
    target: TargetV1, 
    http_artifacts: List[HTTPRequestArtifactV1],
    rules: Optional[List[Dict[str, Any]]] = None
) -> CMSArtifactV1:
    
    t0 = time.perf_counter()
    artifact = CMSArtifactV1(
        cms_id=str(ulid.new()),
        target_id=target.target_id,
        detected_cms="unknown",
        confidence="low",
    )
    
    if not rules:
        rules = [
            {"name": "wordpress", "indicators": [
                {"type": "endpoint", "path": "/wp-login.php", "score": 3},
                {"type": "meta", "content": "wordpress", "score": 3},
                {"type": "body", "content": "/wp-content/", "score": 1}
            ]}
        ]
    
    scores: Dict[str, int] = {}
    evidence_set = set()

    for req in http_artifacts:
        body = (req.response_analysis_snippet or "").lower()
        url = (req.url or "").lower()
        status = req.status_code or 0
        
        for rule in rules:
            cms_name = str(rule.get("name", "unknown"))
            indicators = rule.get("indicators")
            
            # Runtime guard
            if not isinstance(indicators, list):
                continue
            
            if cms_name not in scores: scores[cms_name] = 0
            
            for ind in indicators:
                if not isinstance(ind, dict): continue

                matched = False
                itype = str(ind.get("type", "unknown"))
                path = ind.get("path")
                content = ind.get("content", "").lower()
                score = int(ind.get("score", 1))

                if itype == "endpoint":
                    if path and path in url and status == 200:
                        matched = True
                elif itype == "meta":
                    # Matching durci
                    if content and "<meta" in body and "content=" in body and content in body:
                        matched = True
                elif itype == "body":
                    if content and content in body:
                        matched = True
                
                if matched:
                    scores[cms_name] += score
                    val = path or content or "match"
                    evidence_set.add(f"{itype}: {val}")

    if scores:
        best_cms = max(scores, key=scores.get)
        best_score = scores[best_cms]
        
        if best_score >= 3:
            artifact.detected_cms = best_cms # type: ignore
            artifact.confidence = "high"
        elif best_score >= 1:
            artifact.detected_cms = best_cms # type: ignore
            artifact.confidence = "medium"

    artifact.evidence = sorted(evidence_set)
    artifact.timings_ms = int((time.perf_counter() - t0) * 1000)
    return artifact