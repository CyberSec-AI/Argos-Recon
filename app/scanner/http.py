from __future__ import annotations

import asyncio
import time
from typing import List, Optional
from urllib.parse import urlparse

import httpx
import ulid

from app.schemas.types import HTTPRequestArtifactV1, TargetV1, TimingsMs


def _build_url(target: TargetV1, path: str) -> str:
    base = target.canonical_url.rstrip("/")
    if not base:
        scheme = target.scheme or "https"
        base = f"{scheme}://{target.host}"
    clean_path = path if path.startswith("/") else f"/{path}"
    return f"{base}{clean_path}"


async def _fetch_single(
    target: TargetV1,
    path: str,
    max_bytes: int,
    client: httpx.AsyncClient,
    semaphore: Optional[asyncio.Semaphore] = None,
) -> HTTPRequestArtifactV1:

    url = _build_url(target, path)
    t0 = time.perf_counter()

    parsed = urlparse(url)
    is_tls = parsed.scheme.lower() == "https"
    real_host = parsed.hostname or target.host
    real_port = parsed.port if parsed.port else (443 if is_tls else 80)

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
        timings_ms=TimingsMs(),
    )

    async def _execute_request():
        try:
            # STREAMING STRICT O(n)
            async with client.stream("GET", url) as response:
                req_art.status_code = response.status_code
                req_art.effective_url = str(response.url)
                req_art.headers = dict(response.headers)

                buffer = bytearray()
                truncated = False

                async for chunk in response.aiter_bytes():
                    remaining = max_bytes - len(buffer)
                    if remaining <= 0:
                        truncated = True
                        break

                    chunk_to_add = chunk[:remaining]
                    buffer.extend(chunk_to_add)

                    if len(chunk) > remaining:
                        truncated = True
                        break

                req_art.response_truncated = truncated
                final_bytes = bytes(buffer)

                try:
                    text_sample = final_bytes.decode("utf-8", errors="replace")
                    req_art.response_analysis_snippet = text_sample[:2048]
                except Exception:
                    pass
        except Exception as e:
            req_art.error = str(e)

    if semaphore:
        async with semaphore:
            await _execute_request()
    else:
        await _execute_request()

    duration = int((time.perf_counter() - t0) * 1000)
    req_art.timings_ms = TimingsMs(total=duration)
    return req_art


async def fetch_http_baseline(
    target: TargetV1, response_raw_max_bytes: int, client: httpx.AsyncClient
) -> HTTPRequestArtifactV1:
    return await _fetch_single(target, "/", response_raw_max_bytes, client)


async def probe_paths(
    target: TargetV1,
    paths: List[str],
    response_raw_max_bytes: int,
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
) -> List[HTTPRequestArtifactV1]:

    tasks = [
        _fetch_single(target, p, response_raw_max_bytes, client, semaphore)
        for p in paths
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    final_artifacts = []
    for i, res in enumerate(results):
        if isinstance(res, Exception):
            url_attempt = _build_url(target, paths[i])
            err_art = HTTPRequestArtifactV1(
                request_id=str(ulid.new()),
                target_id=target.target_id,
                url=url_attempt,
                method="GET",
                error=f"Probe crash: {str(res)}",
                timings_ms=TimingsMs(total=0),
            )
            final_artifacts.append(err_art)
        else:
            final_artifacts.append(res)
    return final_artifacts
