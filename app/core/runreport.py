from __future__ import annotations

import hashlib
from datetime import datetime

from app.core.config import ENGINE_VERSION
from app.schemas.context import ScanContext
from app.schemas.runreport_v1 import (
    FindingCountsV1,
    ReportErrorV1,
    RunReportArtifactsV1,
    RunReportSNR,  # Import nouveau modèle
    RunReportSummaryV1,
    RunReportV1,
)


def build_report_from_context(
    ctx: ScanContext, finished_at: datetime, duration_ms: int
) -> RunReportV1:
    # 1. Counts
    counts_map = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in ctx.findings:
        sev = f.severity.lower()
        if sev in counts_map:
            counts_map[sev] += 1
        else:
            counts_map["info"] += 1

    # 2. Tri & Verdict
    severity_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    sorted_findings = sorted(
        ctx.findings,
        key=lambda f: (severity_rank.get(f.severity.lower(), 0), f.score.total),
        reverse=True,
    )

    verdict = "Clean"
    if sorted_findings:
        if any(f.severity.lower() in ("critical", "high") for f in sorted_findings):
            verdict = "Issues Found"
        else:
            verdict = "Warnings"

    top_findings = [f.title for f in sorted_findings if f.severity.lower() in ("critical", "high")]
    tls_list = [ctx.tls] if ctx.tls else []

    artifacts_section = RunReportArtifactsV1(
        requests=ctx.http, tls=tls_list, dns=ctx.dns, cms=ctx.cms
    )

    # 3. Conversion des erreurs pour le rapport
    report_errors = []
    for e in ctx.errors:
        report_errors.append(
            ReportErrorV1(
                component=e.component,
                error_type=e.error_type,
                message=e.message,
                timestamp=e.timestamp.isoformat(),
            )
        )

    # Fingerprinting
    target_canon = ctx.target.canonical_url
    target_fp = f"sha256:{hashlib.sha256(target_canon.encode()).hexdigest()}"
    finding_fps = [
        {
            "finding_id": f.finding_id,
            "fingerprint": f"sha256:{hashlib.sha256((f.finding_id + f.title).encode()).hexdigest()}",
        }
        for f in ctx.findings
    ]

    return RunReportV1(
        schema_version="runreport.v1",
        run_id=ctx.run_id,
        engine={"name": "recon-assistant", "version": ENGINE_VERSION},
        time={
            "started_at": ctx.started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "duration_ms": duration_ms,
        },
        operator={"type": "user", "id": "local"},
        scope={"intent": "recon", "targets": [ctx.target.model_dump()]},
        summary=RunReportSummaryV1(
            finding_counts=FindingCountsV1(**counts_map),
            top_findings=top_findings,
            snr=RunReportSNR(
                signals_total=len(ctx.signals),
                findings_total=len(ctx.findings),
                requests_total=len(ctx.http),
            ),
            verdict=verdict,
        ),
        # Injection des erreurs
        errors=report_errors,
        delta={
            "delta_ready": True,
            "target_fingerprint": target_fp,
            "finding_fingerprints": finding_fps,
        },
        artifacts=artifacts_section,
        signals=ctx.signals,
        findings=ctx.findings,
    )
