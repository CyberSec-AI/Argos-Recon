from __future__ import annotations

import ulid
import hashlib
# Suppression de 'import time' inutile ici
from typing import List, Optional

from app.schemas.runreport_v1 import RunReportV1, RunReportArtifactsV1, RunReportSummaryV1, RunReportSNR, FindingCountsV1
from app.schemas.types import TLSArtifactV1, HTTPRequestArtifactV1, SignalV1, DNSArtifactV1
from app.schemas.finding_v1 import FindingV1

def build_report(
    target_raw: dict,
    tls_artifact: TLSArtifactV1,
    http_artifacts: List[HTTPRequestArtifactV1],
    signals: List[SignalV1],
    findings: List[FindingV1],
    started_at: str,
    finished_at: str,
    duration_ms: int,
    dns_artifact: Optional[DNSArtifactV1] = None
) -> RunReportV1:
    
    # 1. Génération ID Run
    run_id_val = str(ulid.new())

    # 2. Stats
    counts = {k: 0 for k in ["critical", "high", "medium", "low", "info"]}
    for f in findings:
        counts[f.severity] += 1
        
    top_findings = [f.finding_id for f in findings if f.severity in ("critical", "high")]
    
    verdict = "Clean"
    if findings:
        verdict = findings[0].title 

    # 3. Artefacts (Injection native)
    artifacts_section = RunReportArtifactsV1(
        requests=http_artifacts,
        tls=[tls_artifact] if tls_artifact.ip else [],
        dns=dns_artifact
    )
    
    # 4. Fingerprints
    # Target FP : URL Canonique
    target_fp = f"sha256:{hashlib.sha256(target_raw['canonical_url'].encode()).hexdigest()}"
    
    # Run FP : Basé sur l'ULID (unique et temporel), plus fiable que time.time()
    run_fp = f"sha256:{hashlib.sha256(run_id_val.encode()).hexdigest()}"

    # Finding FP : Basé sur ID + Titre pour unicité et traçabilité
    finding_fps = [
        {"finding_id": f.finding_id, "fingerprint": f"sha256:{hashlib.sha256((f.finding_id + f.title).encode()).hexdigest()}"} 
        for f in findings
    ]

    return RunReportV1(
        schema_version="runreport.v1",
        run_id=run_id_val,
        engine={
            "name": "recon-assistant",
            "engine_version": "0.1.0",
            "build": "dev",
            "profile": "pentest_pro",
            "mode": "low_noise"
        },
        time={
            "started_at": started_at,
            "finished_at": finished_at,
            "duration_ms": duration_ms
        },
        operator={
            "type": "user",
            "id": "usr_local",
            "org_id": "org_local"
        },
        scope={
            "intent": "recon",
            "targets": [target_raw],
            "guardrails": {
                "max_requests": 50,
                "timeouts_ms": {"dns": 2000, "tls": 4000, "http": 8000},
                "ssrf_protection": {"block_private_ranges": True, "block_link_local": True, "block_loopback": True},
                "leak_checks_mode": "opt_in",
                "response_raw_policy": "on_small",
                "response_raw_max_bytes": 262144
            }
        },
        summary=RunReportSummaryV1(
            finding_counts=FindingCountsV1(**counts),
            top_findings=top_findings,
            snr=RunReportSNR(
                signals_total=len(signals),
                findings_total=len(findings),
                requests_total=len(http_artifacts)
            ),
            verdict=verdict
        ),
        delta={
            "delta_ready": True,
            "fingerprint_algo": "v1:sha256",
            "normalization": {
                "version": "norm.v1",
                "url_normalization": "lowercase_host, strip_default_ports, ensure_trailing_slash",
                "header_normalization": "lowercase_keys, trim_values",
                "tls_normalization": "sorted_san, normalized_issuer_dn"
            },
            "target_fingerprint": target_fp,
            "run_fingerprint": run_fp,
            "finding_fingerprints": finding_fps
        },
        artifacts=artifacts_section,
        signals=signals,
        findings=findings
    )