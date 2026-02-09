from __future__ import annotations

import re
from typing import List

from app.schemas.types import SignalV1, TLSArtifactV1, HTTPRequestArtifactV1

NONPROD_RE = re.compile(r"\b(dev|staging|stage|test|qa|uat|preprod|nonprod|internal|local)\b", re.IGNORECASE)
VERSION_RE = re.compile(r"\d+\.\d+(\.\d+)?")
WAF_PATTERNS = re.compile(r"(akamai|edgesuite|cloudfront|cloudflare|imperva|incapsula|fastly|sucuri|shield|bot\s*manager|waf)", re.IGNORECASE)

DOC_PATH_KEYWORDS = ["swagger", "openapi", "api-docs", "graphql", "graphiql", "redoc"]
API_SWAGGER_UI_RE = re.compile(r"(swagger-ui|swagger\s+ui|redoc|graphiql)", re.IGNORECASE)

def extract_signals(tls_artifact: TLSArtifactV1, http_artifacts: List[HTTPRequestArtifactV1]) -> List[SignalV1]:
    signals: list[SignalV1] = []
    
    baseline = next((h for h in http_artifacts if "baseline" in h.tags), http_artifacts[0] if http_artifacts else None)
    if not baseline: return signals

    # TLS
    cn = tls_artifact.cn or ""
    san = tls_artifact.san or []
    tls_subject_mismatch = bool(NONPROD_RE.search(cn)) or any(bool(NONPROD_RE.search(x)) for x in san)
    signals.append(SignalV1(signal_id="tls.subject_mismatch", source="tls", target_id=tls_artifact.target_id, value=tls_subject_mismatch, weight=1, signal_confidence=0.9, evidence_refs=["ev_tls_subject"] if tls_subject_mismatch else []))

    issuer_dn = (tls_artifact.issuer_dn or "").lower().strip()
    issuer_type = tls_artifact.self_signed or ("enterprise" in issuer_dn) or ("internal" in issuer_dn)
    signals.append(SignalV1(signal_id="tls.issuer_type", source="tls", target_id=tls_artifact.target_id, value=bool(issuer_type), weight=1, signal_confidence=0.7, evidence_refs=["ev_tls_issuer"] if issuer_type else []))

    # HTTP Baseline
    h = baseline.headers or {}
    verbose = False
    for key in ("server", "x-powered-by", "x-aspnet-version"):
        v = h.get(key, "")
        if v and VERSION_RE.search(v):
            verbose = True
            break
    signals.append(SignalV1(signal_id="http.header.verbose", source="http", target_id=baseline.target_id, value=verbose, weight=1, signal_confidence=0.9, evidence_refs=["ev_http_hdr_verbose"] if verbose else [], artifact_ref=baseline.request_id if verbose else None))

    latency = (baseline.timings_ms.total or 0) > 500
    signals.append(SignalV1(signal_id="http.response.latency", source="http", target_id=baseline.target_id, value=latency, weight=1, signal_confidence=0.6, evidence_refs=[], artifact_ref=baseline.request_id if latency else None))

    # --- API Signals ---
    spec_found_ref = None
    ui_found_ref = None
    api_protected = False
    
    for art in http_artifacts:
        # CORRECTION V3.4 : On accepte aussi la baseline pour détecter l'UI à la racine
        relevant_tags = ["api_recon", "probe", "baseline"]
        if not any(tag in art.tags for tag in relevant_tags): 
            continue

        is_doc_path = any(k in art.url.lower() for k in DOC_PATH_KEYWORDS)

        if art.status_code == 200:
            snippet = (art.response_analysis_snippet or "").lower()
            ct = (art.headers.get("content-type", "") or "").lower()
            
            # 1. Spec (High)
            looks_like_spec_ct = "json" in ct or "yaml" in ct or "text/plain" in ct
            looks_like_spec_url = any(k in art.url.lower() for k in ["openapi", "swagger", "api-docs"])
            
            if looks_like_spec_ct or looks_like_spec_url:
                has_api_key = "openapi" in snippet or "swagger" in snippet
                has_structure = any(k in snippet for k in ["paths", "components", "definitions", "schemes"])
                
                if has_api_key and has_structure and not spec_found_ref:
                    spec_found_ref = art.request_id

            # 2. UI (Medium)
            if API_SWAGGER_UI_RE.search(snippet):
                if not ui_found_ref:
                    ui_found_ref = art.request_id
        
        elif art.status_code in (401, 403) and is_doc_path:
            api_protected = True

    if spec_found_ref:
        signals.append(SignalV1(signal_id="surface.api.spec_exposed", source="http", target_id=baseline.target_id, value=True, weight=2, signal_confidence=0.99, evidence_refs=[], artifact_ref=spec_found_ref))
    
    if ui_found_ref:
        signals.append(SignalV1(signal_id="surface.api.ui_exposed", source="http", target_id=baseline.target_id, value=True, weight=1, signal_confidence=0.95, evidence_refs=[], artifact_ref=ui_found_ref))

    if api_protected and not (spec_found_ref or ui_found_ref):
        signals.append(SignalV1(signal_id="surface.api.docs_protected", source="http", target_id=baseline.target_id, value=True, weight=0, signal_confidence=0.8, evidence_refs=[]))

    # WAF
    is_blocked = baseline.status_code in (403, 406, 429, 503)
    waf_detected = False
    if is_blocked:
        body_str = baseline.response_analysis_snippet or ""
        if WAF_PATTERNS.search(str(h)) or WAF_PATTERNS.search(body_str):
            waf_detected = True

    if waf_detected:
        signals.append(SignalV1(signal_id="http.blocked.waf_suspected", source="http", target_id=baseline.target_id, value=True, weight=0, signal_confidence=0.8, evidence_refs=[], artifact_ref=baseline.request_id))

    return signals