from __future__ import annotations

import asyncio
import random
import time
from typing import List, Optional, Tuple
from urllib.parse import urlparse

import httpx
import ulid

from app.core.config import (
    BACKOFF_FACTOR,
    ENABLE_JITTER,
    GLOBAL_RATE_LIMIT,
    JITTER_RANGE,
    MAX_RETRIES,
)
from app.core.stealth_profiles import STEALTH_PROFILES
from app.schemas.types import HTTPRequestArtifactV1, TargetV1, TimingsMs

_last_reserved_time = 0.0
_scheduler_lock = asyncio.Lock()


def _build_url(target: TargetV1, path: str) -> str:
    base = target.canonical_url.rstrip("/")
    if not base:
        scheme = target.scheme or "https"
        base = f"{scheme}://{target.host}"
    return f"{base}{path if path.startswith('/') else '/' + path}"


async def _global_throttle() -> None:
    global _last_reserved_time
    async with _scheduler_lock:
        now = time.monotonic()
        next_slot = max(now, _last_reserved_time) + GLOBAL_RATE_LIMIT
        wait_time = next_slot - now
        _last_reserved_time = next_slot
        actual_wait = max(0.0, wait_time)
        if ENABLE_JITTER:
            actual_wait += random.uniform(*JITTER_RANGE)
        if actual_wait > 0:
            await asyncio.sleep(actual_wait)


async def _fetch_single(
    target: TargetV1,
    path: str,
    max_bytes: int,
    client: httpx.AsyncClient,
    semaphore: Optional[asyncio.Semaphore] = None,
) -> HTTPRequestArtifactV1:
    url = _build_url(target, path)
    parsed = urlparse(url)
    t0 = time.perf_counter()
    is_h = parsed.scheme == "https"

    req_art = HTTPRequestArtifactV1(
        request_id=str(ulid.new()),
        target_id=target.target_id,
        url=url,
        effective_url=url,
        host=parsed.hostname or target.host,
        ip=target.resolved_ips[0] if target.resolved_ips else "",
        port=parsed.port or (443 if is_h else 80),
        tls=is_h,
        method="GET",
        response_truncated=False,
        timings_ms=TimingsMs(),
    )

    attempts = 0
    current_retry_delay = 0.0
    retryable_codes = {429, 502, 503, 504}

    while attempts <= MAX_RETRIES:
        if current_retry_delay > 0:
            await asyncio.sleep(current_retry_delay)
            current_retry_delay = 0.0
        else:
            await _global_throttle()

        try:
            headers = dict(random.choice(STEALTH_PROFILES))

            async def do_req(h: dict[str, str]) -> Tuple[str, int, Optional[str]]:
                async with client.stream("GET", url, headers=h) as resp:
                    if resp.status_code in retryable_codes:
                        return "retry", resp.status_code, resp.headers.get("Retry-After")
                    req_art.status_code = resp.status_code
                    req_art.effective_url = str(resp.url)
                    req_art.headers = {k.lower(): str(v) for k, v in resp.headers.items()}
                    buffer = bytearray()
                    async for chunk in resp.aiter_bytes():
                        if len(buffer) + len(chunk) > max_bytes:
                            buffer.extend(chunk[: max_bytes - len(buffer)])
                            req_art.response_truncated = True
                            break
                        buffer.extend(chunk)
                    req_art.response_analysis_snippet = buffer.decode("utf-8", errors="replace")[
                        :2048
                    ]
                    return "ok", resp.status_code, None

            if semaphore:
                async with semaphore:
                    status, code, r_val = await do_req(headers)
            else:
                status, code, r_val = await do_req(headers)

            if status == "retry":
                attempts += 1
                if attempts > MAX_RETRIES:
                    req_art.error = f"MAX_RETRY_HTTP_{code}"
                    break
                current_retry_delay = (
                    float(r_val) if (r_val and r_val.isdigit()) else float(BACKOFF_FACTOR**attempts)
                )
                continue
            break
        except Exception as e:
            attempts += 1
            if attempts > MAX_RETRIES:
                req_art.error = f"EXC:{type(e).__name__}"
                break
            current_retry_delay = float(BACKOFF_FACTOR**attempts)

    req_art.timings_ms.total = int((time.perf_counter() - t0) * 1000)
    return req_art


async def fetch_http_baseline(
    target: TargetV1, max_bytes: int, client: httpx.AsyncClient
) -> HTTPRequestArtifactV1:
    return await _fetch_single(target, "/", max_bytes, client)


async def probe_paths(
    target: TargetV1,
    paths: List[str],
    max_bytes: int,
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
) -> List[HTTPRequestArtifactV1]:
    tasks = [_fetch_single(target, p, max_bytes, client, semaphore) for p in paths]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    final: List[HTTPRequestArtifactV1] = []
    for i, res in enumerate(results):
        if isinstance(res, HTTPRequestArtifactV1):
            final.append(res)
        else:
            url = _build_url(target, paths[i])
            p = urlparse(url)
            ish = p.scheme == "https"
            final.append(
                HTTPRequestArtifactV1(
                    request_id=str(ulid.new()),
                    target_id=target.target_id,
                    url=url,
                    effective_url=url,
                    host=p.hostname or target.host,
                    ip=target.resolved_ips[0] if target.resolved_ips else "",
                    port=p.port or (443 if ish else 80),
                    tls=ish,
                    method="GET",
                    error=f"CRASH:{str(res)}",
                    timings_ms=TimingsMs(),
                )
            )
    return final
