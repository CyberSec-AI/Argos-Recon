from __future__ import annotations
import time
import httpx
import ulid
import asyncio
from typing import List
from app.schemas.types import HTTPRequestArtifactV1, TargetV1
from app.core.config import HTTP_TIMEOUT_TOTAL

# Sémaphore global pour limiter la concurrence HTTP
http_sem = asyncio.Semaphore(10)

async def _fetch_single(target: TargetV1, path: str, max_bytes: int) -> HTTPRequestArtifactV1:
    url = f"{target.canonical_url.rstrip('/')}{path}"
    t0 = time.perf_counter()
    
    req_art = HTTPRequestArtifactV1(
        request_id=str(ulid.new()),
        target_id=target.target_id,
        url=url,
        effective_url=url,
        host=target.host,
        ip=target.resolved_ips[0] if target.resolved_ips else "",
        port=target.port or (443 if target.scheme == "https" else 80),
        tls=(target.scheme == "https"),
        method="GET",
        raw=""
    )

    async with http_sem:
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=HTTP_TIMEOUT_TOTAL) as client:
                resp = await client.get(url)
                
                req_art.status_code = resp.status_code
                req_art.effective_url = str(resp.url)
                # Conversion headers (multidict -> dict)
                req_art.headers = dict(resp.headers)
                
                # Gestion Body safe
                content = resp.content
                if len(content) > max_bytes:
                    req_art.response_truncated = True
                    content = content[:max_bytes]
                
                # Snippet (premiers 2048 chars)
                try:
                    text_sample = content.decode("utf-8", errors="replace")
                    req_art.response_analysis_snippet = text_sample[:2048]
                except:
                    pass

        except Exception as e:
            req_art.error = str(e)

    req_art.timings_ms.total = int((time.perf_counter() - t0) * 1000)
    return req_art

async def fetch_http_baseline(target: TargetV1, response_raw_max_bytes: int) -> HTTPRequestArtifactV1:
    return await _fetch_single(target, "/", response_raw_max_bytes)

async def probe_paths(target: TargetV1, paths: List[str], response_raw_max_bytes: int) -> List[HTTPRequestArtifactV1]:
    tasks = [_fetch_single(target, p, response_raw_max_bytes) for p in paths]
    return await asyncio.gather(*tasks)