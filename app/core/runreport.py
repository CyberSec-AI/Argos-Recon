from __future__ import annotations

from datetime import datetime

from app.core.config import ENGINE_VERSION
from app.schemas.context import ScanContext
from app.schemas.runreport_v1 import (
    FindingCountsV1,
    ReportErrorV1,
    RunReportArtifactsV1,
    RunReportSNR,
    RunReportSummaryV1,
    RunReportV1,
)


def build_report_from_context(
    ctx: ScanContext, finished_at: datetime, duration_ms: int
) -> RunReportV1:
    # 1. Counts
    counts = FindingCountsV1(
        critical=sum(1 for f in ctx.findings if f.severity == "critical"),
        high=sum(1 for f in ctx.findings if f.severity == "high"),
        medium=sum(1 for f in ctx.findings if f.severity == "medium"),
        low=sum(1 for f in ctx.findings if f.severity == "low"),
        info=sum(1 for f in ctx.findings if f.severity == "info"),
    )

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

    artifacts_section = RunReportArtifactsV1(
        requests=ctx.http,
        tls=[ctx.tls] if ctx.tls else [],
        dns=[ctx.dns] if ctx.dns else [],
        cms=[ctx.cms] if ctx.cms else [],
    )

    # 3. Conversion des erreurs pour le rapport
    report_errors = [
        ReportErrorV1(
            component=e.component,
            error_type=e.error_type,
            message=e.message,
            timestamp=e.timestamp.isoformat(),
        )
        for e in ctx.errors
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
            finding_counts=counts,
            top_findings=top_findings,
            snr=RunReportSNR(
                signals_total=len(ctx.signals),
                findings_total=len(ctx.findings),
                requests_total=len(ctx.http),
            ),
            verdict=verdict,
        ),
        errors=report_errors,
        artifacts=artifacts_section,
        signals=ctx.signals,
        findings=ctx.findings,
    )
