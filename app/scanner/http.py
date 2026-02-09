from __future__ import annotations

import base64
import hashlib
import time
from urllib.parse import urlparse

import httpx
import ulid

from app.schemas.types import HTTPRequestArtifactV1, TimingsMs


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


async def fetch_http_baseline(target: dict, response_raw_max_bytes: int = 262144) -> HTTPRequestArtifactV1:
    url = target["canonical_url"]
    host = target["host"]
    ip = target["resolved_ips"][0]
    port = target["port"]
    use_tls = (target["scheme"] == "https")

    # UA standard (compat) : réduit certains 403 "bot"
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
    accept_lang = "en-US,en;q=0.9"

    headers = {
        "Host": host,
        "User-Agent": ua,
        "Accept": accept,
        "Accept-Language": accept_lang,
        "Connection": "close"
    }

    path = urlparse(url).path or "/"
    if urlparse(url).query:
        path = f"{path}?{urlparse(url).query}"

    # Requête brute alignée avec ce qu'on envoie (audit-ready)
    raw_req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {ua}\r\n"
        f"Accept: {accept}\r\n"
        f"Accept-Language: {accept_lang}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()

    t0 = time.perf_counter()
    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=httpx.Timeout(8.0),
        verify=False,
    ) as client:
        r = await client.get(url, headers=headers)
    t1 = time.perf_counter()

    total_ms = int((t1 - t0) * 1000)

    # Normalisation headers
    norm_headers = {k.lower(): str(v).strip() for k, v in r.headers.items()}

    # response_raw policy: on_small <= 256KB, sinon hash + truncated
    content = r.content or b""
    response_raw = None
    response_truncated = False
    response_hash = None

    if len(content) <= response_raw_max_bytes:
        response_raw = _b64(content)
        response_hash = f"sha256:{hashlib.sha256(content).hexdigest()}"
    else:
        response_truncated = True
        response_hash = f"sha256:{hashlib.sha256(content).hexdigest()}"

    return HTTPRequestArtifactV1(
        request_id=str(ulid.new()),
        target_id=target["target_id"],
        url=url,
        host=host,
        ip=ip,
        port=port,
        tls=use_tls,
        protocol="HTTP/1.1",
        method="GET",
        raw=_b64(raw_req),
        raw_encoding="base64",
        response_raw=response_raw,
        response_raw_encoding="base64" if response_raw is not None else None,
        response_truncated=response_truncated,
        response_hash=response_hash,
        status_code=r.status_code,
        headers=norm_headers,
        timings_ms=TimingsMs(total=total_ms),
        tags=["baseline", "headers"]
    )
