from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import List, Optional

import ulid

from app.schemas.runreport_v1 import RunReportV1, TimeInfoV1, ScopeV1, SummaryV1, DeltaV1, ArtifactsV1, GuardrailsV1
from app.schemas.types import TargetV1, TLSArtifactV1, HTTPRequestArtifactV1, SignalV1
from app.schemas.finding_v1 import FindingV1


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256_obj(obj) -> str:
    data = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def build_report(
    target_raw: dict,
    tls_artifact: TLSArtifactV1,
    http_artifact: HTTPRequestArtifactV1,
    signals: List[SignalV1],
    findings: List[FindingV1],
    started_at: str,
    finished_at: str,
    duration_ms: int
) -> RunReportV1:
    target = TargetV1(
        target_id=target_raw["target_id"],
        input=target_raw["input"],
        canonical_url=target_raw["canonical_url"],
        host=target_raw["host"],
        resolved_ips=target_raw["resolved_ips"],
        ports=target_raw["ports"],
    )

    guardrails = GuardrailsV1(
        max_requests=50,
        leak_checks_mode="opt_in",
        response_raw_policy="on_small",
        response_raw_max_bytes=262144
    )

    scope = ScopeV1(targets=[target], guardrails=guardrails)

    # Summary counts
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.severity] += 1

    summary = SummaryV1(
        finding_counts=counts,
        top_findings=[findings[0].finding_id] if findings else [],
        snr={
            "signals_total": len(signals),
            "findings_total": len(findings),
            "requests_total": 1  # MVP baseline only
        },
        verdict=findings[0].title if findings else "No high-confidence correlated playbook triggered."
    )

    # Delta fingerprints (v1:sha256 + norm.v1)
    delta = DeltaV1(
        delta_ready=True,
        fingerprint_algo="v1:sha256",
        normalization={
            "version": "norm.v1",
            "url_normalization": "lowercase_host, strip_default_ports, ensure_trailing_slash",
            "header_normalization": "lowercase_keys, trim_values",
            "tls_normalization": "sorted_san, normalized_issuer_dn"
        }
    )

    # Stable-ish target fingerprint
    delta.target_fingerprint = _sha256_obj({
        "host": target.host.lower(),
        "canonical_url": target.canonical_url,
        "ports": target.ports,
    })

    # Run fingerprint
    delta.run_fingerprint = _sha256_obj({
        "target_fingerprint": delta.target_fingerprint,
        "signals": sorted([{"id": s.signal_id, "v": s.value} for s in signals], key=lambda x: x["id"]),
        "top_findings": [f.playbook_id for f in findings],
    })

    # Finding fingerprints
    delta.finding_fingerprints = []
    for f in findings:
        fp = _sha256_obj({
            "playbook_id": f.playbook_id,
            "target": target.canonical_url,
            "signals": sorted([{"id": s.signal_id, "v": s.value} for s in f.signals], key=lambda x: x["id"]),
        })
        delta.finding_fingerprints.append({"finding_id": f.finding_id, "fingerprint": fp})

    artifacts = ArtifactsV1(
        requests=[http_artifact],
        tls=[tls_artifact]
    )

    return RunReportV1(
        run_id=str(ulid.new()),
        time=TimeInfoV1(started_at=started_at, finished_at=finished_at, duration_ms=duration_ms),
        operator={"type": "user", "id": "usr_local", "org_id": "org_local"},
        scope=scope,
        summary=summary,
        delta=delta,
        artifacts=artifacts,
        signals=signals,
        findings=findings
    )
