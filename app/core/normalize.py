from __future__ import annotations

import ipaddress
import socket
import asyncio
from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse

import ulid


NONPROD_KEYWORDS = ("dev", "staging", "stage", "test", "qa", "uat", "preprod", "nonprod", "internal", "local")


def _canonicalize_url(input_url: str) -> str:
    u = input_url.strip()
    if not u:
        raise ValueError("empty url")

    if "://" not in u:
        u = "https://" + u

    p = urlparse(u)
    if p.scheme not in ("http", "https"):
        raise ValueError("unsupported scheme")

    host = (p.hostname or "").strip().lower()
    if not host:
        raise ValueError("missing host")

    port = p.port
    scheme = p.scheme

    # remove default ports
    netloc = host
    if port and not ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)):
        netloc = f"{host}:{port}"

    path = p.path or "/"
    if not path.endswith("/"):
        # we normalize only for root-like paths; keep it simple for MVP
        if path == "":
            path = "/"

    # Drop fragments; keep query for now (unused MVP)
    return urlunparse((scheme, netloc, path, "", p.query or "", ""))


def _is_blocked_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    if addr.is_loopback:
        return True
    if addr.is_link_local:
        return True
    if addr.is_private:
        return True
    return False


async def _resolve_ips(host: str) -> list[str]:
    # DNS resolution is blocking; run in thread
    def _resolve() -> list[str]:
        ips: set[str] = set()
        for family, _, _, _, sockaddr in socket.getaddrinfo(host, None):
            if family == socket.AF_INET:
                ips.add(sockaddr[0])
            elif family == socket.AF_INET6:
                ips.add(sockaddr[0])
        return sorted(ips)

    return await asyncio.to_thread(_resolve)


async def normalize_target(input_url: str) -> dict:
    """
    Returns dict with:
      target_id, input, canonical_url, host, resolved_ips, ports, scheme
    or raises ValueError.
    """
    canonical = _canonicalize_url(input_url)
    p = urlparse(canonical)
    host = p.hostname or ""
    scheme = p.scheme
    port = p.port or (443 if scheme == "https" else 80)

    ips = await _resolve_ips(host)
    if not ips:
        raise ValueError("dns resolution failed")

    # SSRF protection: block if any resolved ip is private/loopback/link-local
    for ip in ips:
        if _is_blocked_ip(ip):
            raise ValueError(f"ssrf protection triggered for ip {ip}")

    return {
        "target_id": str(ulid.new()),
        "input": input_url,
        "canonical_url": canonical,
        "host": host,
        "resolved_ips": ips,
        "ports": [port],
        "scheme": scheme,
        "port": port
    }
