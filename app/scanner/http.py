from __future__ import annotations

import asyncio
import random
import time
from typing import Optional

import httpx
import ulid

from app.core.config import (
    BACKOFF_FACTOR,
    ENABLE_JITTER,
    GLOBAL_RATE_LIMIT,
    JITTER_RANGE,
    MAX_RETRIES,
    USER_AGENT_POOL,
)
from app.schemas.types import HTTPRequestArtifactV1, TargetV1, TimingsMs

# Etat global du scheduler pour le processus
_last_reserved_time = 0.0
_scheduler_lock = asyncio.Lock()


def _build_url(target: TargetV1, path: str) -> str:
    """Helper interne pour la construction d'URL."""
    base = target.canonical_url.rstrip("/")
    if not base:
        scheme = target.scheme or "https"
        base = f"{scheme}://{target.host}"
    clean_path = path if path.startswith("/") else f"/{path}"
    return f"{base}{clean_path}"


async def _global_throttle():
    """
    A.1 & A.3 : Stealth Scheduler avec réservation de slot et Jitter systématique.
    Garantit un intervalle minimum entre les départs de requêtes.
    """
    global _last_reserved_time
    async with _scheduler_lock:
        now = time.monotonic()

        # Réservation du slot théorique (Slot Reservation Pattern)
        next_slot = max(now, _last_reserved_time) + GLOBAL_RATE_LIMIT
        wait_time = next_slot - now
        _last_reserved_time = next_slot

        # Ajout du Jitter systématique même en cas de retard
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
    t0 = time.perf_counter()

    # Initialisation explicite
    req_art = HTTPRequestArtifactV1(
        request_id=str(ulid.new()),
        target_id=target.target_id,
        url=url,
        effective_url=url,
        method="GET",
        response_truncated=False,  # Initialisation explicite
        timings_ms=TimingsMs(),
    )

    attempts = 0
    current_retry_delay = 0.0
    # Codes d'erreurs transitoires éligibles au retry
    retryable_codes = {429, 502, 503, 504}

    while attempts <= MAX_RETRIES:
        # Gestion du délai (Priorité Retry-After > Global Throttle)
        if current_retry_delay > 0:
            await asyncio.sleep(current_retry_delay)
            current_retry_delay = 0.0
        else:
            await _global_throttle()

        try:
            current_headers = {"User-Agent": random.choice(USER_AGENT_POOL)}

            # Correction B023 : On lie 'current_headers' via un argument par défaut
            async def do_req(h=current_headers):
                async with client.stream("GET", url, headers=h) as resp:
                    if resp.status_code in retryable_codes:
                        return "retry", resp.status_code, resp.headers.get("Retry-After")

                    req_art.status_code = resp.status_code
                    req_art.effective_url = str(resp.url)
                    req_art.headers = dict(resp.headers)

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
                    status, code, r_val = await do_req()
            else:
                status, code, r_val = await do_req()

            if status == "retry":
                # Ne pas "brûler" de tentative si un Retry-After numérique est fourni sur 429
                if not (code == 429 and r_val and r_val.isdigit()):
                    attempts += 1

                if r_val and r_val.isdigit():
                    current_retry_delay = float(r_val)
                else:
                    current_retry_delay = float(BACKOFF_FACTOR**attempts)
                continue

            break

        except Exception as e:
            attempts += 1
            if attempts > MAX_RETRIES:
                req_art.error = f"Max retries reached: {str(e)}"
                break
            current_retry_delay = float(BACKOFF_FACTOR**attempts)

    req_art.timings_ms.total = int((time.perf_counter() - t0) * 1000)
    return req_art


# Les fonctions suivantes restent inchangées mais sont nécessaires pour l'interface du module
async def fetch_http_baseline(
    target: TargetV1, response_raw_max_bytes: int, client: httpx.AsyncClient
) -> HTTPRequestArtifactV1:
    return await _fetch_single(target, "/", response_raw_max_bytes, client)


async def probe_paths(
    target: TargetV1,
    paths: list[str],
    response_raw_max_bytes: int,
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
) -> list[HTTPRequestArtifactV1]:
    tasks = [_fetch_single(target, p, response_raw_max_bytes, client, semaphore) for p in paths]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    final_artifacts: list[HTTPRequestArtifactV1] = []
    for i, res in enumerate(results):
        if isinstance(res, HTTPRequestArtifactV1):
            final_artifacts.append(res)
        else:
            err_msg = str(res) if isinstance(res, Exception) else "Unknown crash"
            err_art = HTTPRequestArtifactV1(
                request_id=str(ulid.new()),
                target_id=target.target_id,
                url=_build_url(target, paths[i]),
                method="GET",
                error=f"Probe crash: {err_msg}",
                timings_ms=TimingsMs(total=0),
            )
            final_artifacts.append(err_art)

    return final_artifacts
