from __future__ import annotations

import re
from typing import List

from app.schemas.types import SignalV1, TLSArtifactV1, HTTPRequestArtifactV1

NONPROD_RE = re.compile(r"\b(dev|staging|stage|test|qa|uat|preprod|nonprod|internal|local)\b", re.IGNORECASE)
VERSION_RE = re.compile(r"\d+\.\d+(\.\d+)?")


def extract_signals(tls_artifact: TLSArtifactV1, http_artifact: HTTPRequestArtifactV1) -> List[SignalV1]:
    signals: list[SignalV1] = []

    # Evidence IDs are local to the finding/report; we’ll keep them stable strings
    ev_tls_subject = "ev_tls_subject"
    ev_http_hdr_verbose = "ev_http_hdr_verbose"

    # TLS subject mismatch / non-prod naming in CN or SAN
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

    # TLS issuer type (simple heuristic: self-signed OR "Enterprise" / "Internal" in issuer DN)
    issuer = (tls_artifact.issuer_dn or "").lower()
    issuer_type = tls_artifact.self_signed or ("enterprise" in issuer) or ("internal" in issuer)

    signals.append(SignalV1(
        signal_id="tls.issuer_type",
        source="tls",
        target_id=tls_artifact.target_id,
        value=bool(issuer_type),
        weight=1,
        signal_confidence=0.7,
        evidence_refs=["ev_tls_issuer"] if issuer_type else []
    ))

    # HTTP verbose header exposure: versions in server/x-powered-by/x-aspnet-version
    h = http_artifact.headers
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

    # HTTP latency (weak signal, not used to trigger PB1 alone)
    latency = (http_artifact.timings_ms.total or 0) > 500
    signals.append(SignalV1(
        signal_id="http.response.latency",
        source="http",
        target_id=http_artifact.target_id,
        value=latency,
        weight=1,
        signal_confidence=0.6,
        evidence_refs=["ev_http_latency"] if latency else [],
        artifact_ref=http_artifact.request_id if latency else None
    ))

    return signals
