from __future__ import annotations

import time
import asyncio
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.core.normalize import normalize_target
from app.scanner.dns import fetch_dns_records
from app.scanner.tls import fetch_tls_facts
from app.scanner.http import fetch_http_baseline, probe_paths
from app.core.signals import extract_signals
from app.core.playbooks.pb1 import evaluate_pb1
from app.core.playbooks.pb2 import evaluate_pb2
from app.core.playbooks.pb3 import evaluate_pb3
from app.core.runreport import build_report

router = APIRouter()

class AnalyzeRequest(BaseModel):
    url: str

API_PROBE_LIST = [
    "/swagger-ui.html", "/swagger-ui/", "/swagger/index.html",
    "/v2/api-docs", "/v3/api-docs", "/api/docs", "/api-docs",
    "/openapi.json", "/openapi.yaml", "/graphql", "/graphiql",
    "/robots.txt", "/sitemap.xml"
]

@router.get("/health")
def health():
    return {"status": "online", "engine_version": "0.1.0"}

@router.post("/analyze")
async def analyze(req: AnalyzeRequest):
    started = time.perf_counter()
    started_at = None

    try:
        started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        target = await normalize_target(req.url)

        # 1. DNS Recon (Async)
        dns_artifact = await asyncio.to_thread(fetch_dns_records, target)

        # 2. HTTP & TLS
        tls_artifact = await fetch_tls_facts(target)
        http_baseline = await fetch_http_baseline(target, response_raw_max_bytes=262144)
        
        # Budget
        MAX_HTTP_REQUESTS = 50 
        BASELINE_COST = 1 
        SAFETY_MARGIN = 1
        remaining_budget = MAX_HTTP_REQUESTS - BASELINE_COST - SAFETY_MARGIN
        safe_probe_list = API_PROBE_LIST[:max(0, remaining_budget)]
        
        probes_artifacts = await probe_paths(target, safe_probe_list, response_raw_max_bytes=262144)
        all_http_artifacts = [http_baseline] + probes_artifacts

        # 3. Intelligence
        signals = extract_signals(tls_artifact, all_http_artifacts)

        findings = []
        f1 = evaluate_pb1(signals, target, tls_id=tls_artifact.tls_id, request_id=http_baseline.request_id)
        if f1: findings.append(f1)
        
        f2 = evaluate_pb2(signals, target, all_http_artifacts)
        if f2: findings.append(f2)
        
        # PB3 : Email Security
        f3 = evaluate_pb3(dns_artifact, target)
        if f3: findings.append(f3)

        finished_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        duration_ms = int((time.perf_counter() - started) * 1000)

        # 4. Reporting
        report = build_report(
            target_raw=target,
            tls_artifact=tls_artifact,
            http_artifacts=all_http_artifacts,
            signals=signals,
            findings=findings,
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=duration_ms,
            dns_artifact=dns_artifact
        )
        
        return report.model_dump()
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        import traceback
        traceback.print_exc()
        # CORRECTION : Syntaxe fermée correctement
        raise HTTPException(status_code=500, detail=f"Scan failed: {type(e).__name__}")