from __future__ import annotations

import base64
import re
from typing import List

from app.schemas.types import SignalV1, TLSArtifactV1, HTTPRequestArtifactV1

NONPROD_RE = re.compile(r"\b(dev|staging|stage|test|qa|uat|preprod|nonprod|internal|local)\b", re.IGNORECASE)
VERSION_RE = re.compile(r"\d+\.\d+(\.\d+)?")

# Patterns WAF/CDN connus dans body/headers
WAF_PATTERNS = re.compile(
    r"(akamai|edgesuite|cloudfront|cloudflare|imperva|incapsula|fastly|sucuri|shield|bot\s*manager|waf)",
    re.IGNORECASE
)


def extract_signals(tls_artifact: TLSArtifactV1, http_artifact: HTTPRequestArtifactV1) -> List[SignalV1]:
    signals: list[SignalV1] = []

    ev_tls_subject = "ev_tls_subject"
    ev_tls_issuer = "ev_tls_issuer"
    ev_http_hdr_verbose = "ev_http_hdr_verbose"
    ev_http_latency = "ev_http_latency"

    # --- TLS: subject mismatch (non-prod naming in CN/SAN)
    cn = tls_artifact.cn or ""
    san = tls_artifact.san or []
    tls_subject_mismatch = bool(NONPROD_RE.search(cn)) or any(bool(NONPROD_RE.search(x)) for x in san)

    signals.append(SignalV1(
        signal_id="tls.subject_mismatch",
        source="tls",
        target_id=tls_artifact.target_id,
        value=tls_subject_mismatch,
        weight=1,
        signal_confidence=0.9,
        evidence_refs=[ev_tls_subject] if tls_subject_mismatch else []
    ))

    # --- TLS: issuer type (only if issuer is known)
    issuer_dn = (tls_artifact.issuer_dn or "").lower().strip()
    issuer_known = bool(issuer_dn)

    issuer_type = False
    if issuer_known:
        issuer_type = tls_artifact.self_signed or ("enterprise" in issuer_dn) or ("internal" in issuer_dn)

    signals.append(SignalV1(
        signal_id="tls.issuer_type",
        source="tls",
        target_id=tls_artifact.target_id,
        value=bool(issuer_type),
        weight=1,
        signal_confidence=0.7,
        evidence_refs=[ev_tls_issuer] if issuer_type else []
    ))

    # --- HTTP: verbose header exposure
    h = http_artifact.headers or {}
    verbose = False
    for key in ("server", "x-powered-by", "x-aspnet-version"):
        v = h.get(key, "")
        if v and VERSION_RE.search(v):
            verbose = True
            break

    signals.append(SignalV1(
        signal_id="http.header.verbose",
        source="http",
        target_id=http_artifact.target_id,
        value=verbose,
        weight=1,
        signal_confidence=0.9,
        evidence_refs=[ev_http_hdr_verbose] if verbose else [],
        artifact_ref=http_artifact.request_id if verbose else None
    ))

    # --- HTTP: latency
    latency = (http_artifact.timings_ms.total or 0) > 500
    signals.append(SignalV1(
        signal_id="http.response.latency",
        source="http",
        target_id=http_artifact.target_id,
        value=latency,
        weight=1,
        signal_confidence=0.6,
        evidence_refs=[ev_http_latency] if latency else [],
        artifact_ref=http_artifact.request_id if latency else None
    ))

    # --- NEW: WAF suspected (explains lack of findings)
    is_blocked = http_artifact.status_code in (403, 406, 429, 503)
    waf_detected = False

    if is_blocked:
        headers_str = str(h)

        body_str = ""
        if http_artifact.response_raw:
            try:
                body_str = base64.b64decode(http_artifact.response_raw).decode("utf-8", errors="ignore")
            except Exception:
                body_str = ""

        if WAF_PATTERNS.search(headers_str) or WAF_PATTERNS.search(body_str):
            waf_detected = True

    if waf_detected:
        signals.append(SignalV1(
            signal_id="http.blocked.waf_suspected",
            source="http",
            target_id=http_artifact.target_id,
            value=True,
            weight=0,  # informatif
            signal_confidence=0.8,
            evidence_refs=[],
            artifact_ref=http_artifact.request_id
        ))

    return signals
