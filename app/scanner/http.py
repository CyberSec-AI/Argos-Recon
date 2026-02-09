from __future__ import annotations

import asyncio
import base64
import hashlib
import time
from urllib.parse import urlparse

import httpx
import ulid

from app.schemas.types import HTTPRequestArtifactV1, TimingsMs


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


async def _perform_request(client: httpx.AsyncClient, target: dict, path: str, response_raw_max_bytes: int, tags: list[str]) -> HTTPRequestArtifactV1:
    parsed = urlparse(target["canonical_url"])
    scheme = parsed.scheme or "https"
    host = parsed.hostname or target["host"]
    
    ips = target.get("resolved_ips") or []
    ip = ips[0] if ips else ""
    
    if target.get("ports") and len(target["ports"]) > 0:
        port = target["ports"][0]
    else:
        port = 443 if scheme == "https" else 80

    use_tls = (scheme == "https")
    
    base_url = target["canonical_url"].rstrip("/")
    full_url = f"{base_url}{path}"
    
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    accept = "text/html,application/json,application/xml;q=0.9,*/*;q=0.8"
    lang = "en-US,en;q=0.9"
    
    headers = { 
        "User-Agent": ua, 
        "Accept": accept, 
        "Accept-Language": lang,
        "Connection": "close" 
    }

    raw_req_display = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {ua}\r\n"
        f"Accept: {accept}\r\n"
        f"Accept-Language: {lang}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()

    t0 = time.perf_counter()
    body_buffer = bytearray()
    snippet_text = ""
    status_code = 0
    res_headers = {}
    response_truncated = False
    effective_url = full_url
    protocol_version = "HTTP/1.1" # Valeur par défaut sûre
    
    try:
        async with client.stream("GET", full_url, headers=headers) as r:
            status_code = r.status_code
            res_headers = {k.lower(): str(v) for k, v in r.headers.items()}
            effective_url = str(r.url)
            
            # Correction V3.1 : Capture robuste de la version HTTP
            protocol_version = getattr(r, "http_version", None) or "HTTP/1.1"
            
            limit_soft = 32 * 1024 
            limit_hard = response_raw_max_bytes
            
            async for chunk in r.aiter_bytes():
                body_buffer.extend(chunk)
                if len(body_buffer) > limit_hard:
                    response_truncated = True
                    del body_buffer[limit_hard:]
                    break
            
            encoding = r.encoding or "utf-8"
            try:
                snippet_text = body_buffer[:limit_soft].decode(encoding, errors="replace")
            except:
                snippet_text = ""

    except httpx.RequestError:
        pass
        
    t1 = time.perf_counter()
    total_ms = int((t1 - t0) * 1000)

    response_content = bytes(body_buffer)
    response_hash = f"sha256:{hashlib.sha256(response_content).hexdigest()}" if response_content else None
    response_raw = _b64(response_content) if response_content else None

    return HTTPRequestArtifactV1(
        request_id=str(ulid.new()), target_id=target["target_id"],
        url=full_url, effective_url=effective_url,
        host=host, ip=ip, port=port, tls=use_tls,
        method="GET", protocol=protocol_version,
        raw=_b64(raw_req_display), raw_encoding="base64",
        response_raw=response_raw, response_raw_encoding="base64" if response_raw else None,
        response_truncated=response_truncated, response_hash=response_hash,
        response_analysis_snippet=snippet_text,
        status_code=status_code, headers=res_headers, timings_ms=TimingsMs(total=total_ms), tags=tags
    )


async def fetch_http_baseline(target: dict, response_raw_max_bytes: int = 262144) -> HTTPRequestArtifactV1:
    async with httpx.AsyncClient(follow_redirects=False, timeout=httpx.Timeout(8.0), verify=False) as client:
        return await _perform_request(client, target, "/", response_raw_max_bytes, ["baseline", "headers"])


async def probe_paths(target: dict, paths: list[str], response_raw_max_bytes: int = 262144) -> list[HTTPRequestArtifactV1]:
    sem = asyncio.Semaphore(10)
    async def limited_probe(client, p):
        async with sem:
            path = p if p.startswith("/") else f"/{p}"
            return await _perform_request(client, target, path, response_raw_max_bytes, ["probe", "api_recon"])

    async with httpx.AsyncClient(follow_redirects=False, timeout=httpx.Timeout(5.0), verify=False) as client:
        tasks = [limited_probe(client, path) for path in paths]
        return await asyncio.gather(*tasks)