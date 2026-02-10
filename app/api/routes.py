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
from app.scanner.cms import detect_cms
from app.core.signals import extract_signals
from app.core.playbooks.pb1 import evaluate_pb1
from app.core.playbooks.pb2 import evaluate_pb2
from app.core.playbooks.pb3 import evaluate_pb3
from app.core.playbooks.pb4 import evaluate_pb4
from app.core.runreport import build_report

router = APIRouter()

class AnalyzeRequest(BaseModel):
    url: str

PROBE_LIST = [
    # API Recon
    "/swagger-ui.html", "/swagger-ui/", "/v2/api-docs", "/openapi.json",
    "/robots.txt", "/sitemap.xml",
    # CMS Recon
    "/wp-login.php",
    "/wp-json/",
    "/xmlrpc.php",
    "/administrator/",
    "/user/login"
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

        # 1. DNS Recon
        dns_artifact = await asyncio.to_thread(fetch_dns_records, target)

        # 2. HTTP & TLS
        tls_artifact = await fetch_tls_facts(target)
        http_baseline = await fetch_http_baseline(target, response_raw_max_bytes=262144)
        
        # Budget
        MAX_HTTP_REQUESTS = 50 
        BASELINE_COST = 1 
        SAFETY_MARGIN = 1
        remaining_budget = MAX_HTTP_REQUESTS - BASELINE_COST - SAFETY_MARGIN
        safe_probe_list = PROBE_LIST[:max(0, remaining_budget)]
        
        probes_artifacts = await probe_paths(target, safe_probe_list, response_raw_max_bytes=262144)
        all_http_artifacts = [http_baseline] + probes_artifacts

        # 3. CMS Detection (NOUVEAU)
        cms_artifact = detect_cms(target, all_http_artifacts)

        # 4. Intelligence
        signals = extract_signals(tls_artifact, all_http_artifacts)

        findings = []
        f1 = evaluate_pb1(signals, target, tls_id=tls_artifact.tls_id, request_id=http_baseline.request_id)
        if f1: findings.append(f1)
        
        f2 = evaluate_pb2(signals, target, all_http_artifacts)
        if f2: findings.append(f2)
        
        f3 = evaluate_pb3(dns_artifact, target)
        if f3: findings.append(f3)

        f4 = evaluate_pb4(dns_artifact, target, all_http_artifacts)
        if f4: findings.append(f4)

        finished_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        duration_ms = int((time.perf_counter() - started) * 1000)

        # 5. Reporting (Wiring Propre)
        report = build_report(
            target_raw=target,
            tls_artifact=tls_artifact,
            http_artifacts=all_http_artifacts,
            signals=signals,
            findings=findings,
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=duration_ms,
            dns_artifact=dns_artifact,
            cms_artifact=cms_artifact # Argument natif
        )
        
        return report.model_dump()
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Scan failed: {type(e).__name__}")