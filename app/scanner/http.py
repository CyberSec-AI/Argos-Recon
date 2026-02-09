from __future__ import annotations

import base64
import hashlib
import time
from urllib.parse import urlparse

import httpx
import ulid
from app.schemas.types import HTTPRequestArtifactV1, TimingsMs


def _b64(s: bytes) -> str:
    return base64.b64encode(s).decode("ascii")


async def fetch_http_baseline(target: dict, response_raw_max_bytes: int = 262144) -> HTTPRequestArtifactV1:
    url = target["canonical_url"]
    host = target["host"]
    ip = target["resolved_ips"][0]
    port = target["port"]
    use_tls = (target["scheme"] == "https")

    headers = {
        "Host": host,
        "User-Agent": "Recon-Engine/0.1.0",
        "Accept": "*/*",
        "Connection": "close"
    }

    # Build a canonical raw request (what we intended to send)
    raw_req = (
        f"GET {urlparse(url).path or '/'} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {headers['User-Agent']}\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()

    t0 = time.perf_counter()
    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=httpx.Timeout(8.0),
        verify=False  # collect facts; don't enforce PKI
    ) as client:
        r = await client.get(url, headers=headers)
    t1 = time.perf_counter()

    total_ms = int((t1 - t0) * 1000)

    # Normalize headers to lowercase keys, string values
    norm_headers = {k.lower(): str(v) for k, v in r.headers.items()}

    # response_raw policy: on_small <= 256KB
    response_raw = None
    response_truncated = False
    response_hash = None

    content = r.content or b""
    if len(content) <= response_raw_max_bytes:
        response_raw = _b64(content)
    else:
        response_truncated = True
        response_hash = f"sha256:{hashlib.sha256(content).hexdigest()}"

    # if we stored response_raw, also compute hash for audit (optional)
    if response_raw is not None:
        response_hash = f"sha256:{hashlib.sha256(content).hexdigest()}"

    return HTTPRequestArtifactV1(
        request_id=str(ulid.new()),
        target_id=target["target_id"],
        url=url,
        host=host,
        ip=ip,
        port=port,
        tls=use_tls,
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
