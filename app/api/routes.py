from __future__ import annotations

import time
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.core.normalize import normalize_target
from app.scanner.tls import fetch_tls_facts
from app.scanner.http import fetch_http_baseline
from app.core.signals import extract_signals
from app.core.playbooks.pb1 import evaluate_pb1
from app.core.runreport import build_report

router = APIRouter()


class AnalyzeRequest(BaseModel):
    url: str


@router.get("/health")
def health():
    return {"status": "online", "engine_version": "0.1.0"}


@router.post("/analyze")
async def analyze(req: AnalyzeRequest):
    started = time.perf_counter()
    started_at = None

    try:
        started_at = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat().replace("+00:00", "Z")

        target = await normalize_target(req.url)

        tls_artifact = await fetch_tls_facts(target)
        http_artifact = await fetch_http_baseline(target, response_raw_max_bytes=262144)

        signals = extract_signals(tls_artifact, http_artifact)

        finding = evaluate_pb1(signals, target, tls_id=tls_artifact.tls_id, request_id=http_artifact.request_id)

        finished_at = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat().replace("+00:00", "Z")
        duration_ms = int((time.perf_counter() - started) * 1000)

        report = build_report(
            target_raw=target,
            tls_artifact=tls_artifact,
            http_artifact=http_artifact,
            signals=signals,
            findings=[finding] if finding else [],
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=duration_ms
        )
        return report.model_dump()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        # MVP: surface error, but do not leak internals in production later
        raise HTTPException(status_code=500, detail=f"Scan failed: {type(e).__name__}")
