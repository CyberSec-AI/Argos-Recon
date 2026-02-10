from __future__ import annotations
import time
import httpx
import ulid
import asyncio
from typing import List
from urllib.parse import urlparse
from app.schemas.types import HTTPRequestArtifactV1, TargetV1, TimingsMs
from app.core.config import HTTP_TIMEOUT_TOTAL

http_sem = asyncio.Semaphore(10)

def _build_url(target: TargetV1, path: str) -> str:
    base = target.canonical_url.rstrip('/')
    if not base:
        scheme = target.scheme or "https"
        base = f"{scheme}://{target.host}"
    clean_path = path if path.startswith("/") else f"/{path}"
    return f"{base}{clean_path}"

async def _fetch_single(target: TargetV1, path: str, max_bytes: int) -> HTTPRequestArtifactV1:
    url = _build_url(target, path)
    t0 = time.perf_counter()
    
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    is_tls = (scheme == "https")
    
    if parsed.port:
        real_port = parsed.port
    else:
        real_port = 443 if is_tls else 80
        
    real_host = parsed.hostname or target.host
    
    req_art = HTTPRequestArtifactV1(
        request_id=str(ulid.new()),
        target_id=target.target_id,
        url=url,
        effective_url=url,
        host=real_host,
        ip=target.resolved_ips[0] if target.resolved_ips else "",
        port=real_port,
        tls=is_tls,
        method="GET",
        raw="",
        timings_ms=TimingsMs()
    )

    async with http_sem:
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=HTTP_TIMEOUT_TOTAL) as client:
                resp = await client.get(url)
                
                req_art.status_code = resp.status_code
                req_art.effective_url = str(resp.url)
                req_art.headers = dict(resp.headers)
                
                content = resp.content
                if len(content) > max_bytes:
                    req_art.response_truncated = True
                    content = content[:max_bytes]
                
                try:
                    text_sample = content.decode("utf-8", errors="replace")
                    req_art.response_analysis_snippet = text_sample[:2048]
                except:
                    pass

        except Exception as e:
            req_art.error = str(e)

    # CORRECTION : Assignation objet
    duration = int((time.perf_counter() - t0) * 1000)
    req_art.timings_ms = TimingsMs(total=duration)
    
    return req_art

async def fetch_http_baseline(target: TargetV1, response_raw_max_bytes: int) -> HTTPRequestArtifactV1:
    return await _fetch_single(target, "/", response_raw_max_bytes)

async def probe_paths(target: TargetV1, paths: List[str], response_raw_max_bytes: int) -> List[HTTPRequestArtifactV1]:
    tasks = [_fetch_single(target, p, response_raw_max_bytes) for p in paths]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    final_artifacts = []
    for i, res in enumerate(results):
        if isinstance(res, Exception):
            url_attempt = _build_url(target, paths[i])
            parsed = urlparse(url_attempt)
            is_tls = (parsed.scheme == "https")
            real_port = parsed.port or (443 if is_tls else 80)
            real_host = parsed.hostname or target.host

            err_art = HTTPRequestArtifactV1(
                request_id=str(ulid.new()),
                target_id=target.target_id,
                url=url_attempt,
                effective_url=url_attempt,
                host=real_host,
                port=real_port,
                tls=is_tls,
                method="GET",
                error=f"Probe crash: {str(res)}",
                # CORRECTION : Assignation objet
                timings_ms=TimingsMs(total=0),
                ip=""
            )
            final_artifacts.append(err_art)
        else:
            final_artifacts.append(res)
            
    return final_artifacts