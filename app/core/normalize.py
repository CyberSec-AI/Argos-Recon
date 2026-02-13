from __future__ import annotations

import asyncio
import socket
from urllib.parse import urlparse, urlunparse

import ulid

from app.schemas.types import TargetV1


async def normalize_target(input_str: str) -> TargetV1:
    """
    Normalise une entrée utilisateur en un objet TargetV1 structuré.
    """
    if not input_str.startswith(("http://", "https://")):
        scheme = "https"
        netloc = input_str
    else:
        parsed = urlparse(input_str)
        scheme = parsed.scheme
        netloc = parsed.netloc

    if ":" in netloc and not netloc.startswith("["):
        host, port_str = netloc.rsplit(":", 1)
        main_port = int(port_str)
    else:
        host = netloc
        main_port = 443 if scheme == "https" else 80

    canonical_url = urlunparse((scheme, netloc, "/", "", "", ""))

    ips: set[str] = set()
    try:
        loop = asyncio.get_event_loop()
        # Correction de la typo : getaddrinfo (sans underscore)
        addrs = await loop.getaddrinfo(host, main_port, family=socket.AF_INET)
        for addr in addrs:
            ips.add(str(addr[4][0]))
    except Exception:
        pass

    ports: set[int] = {main_port}

    return TargetV1(
        target_id=str(ulid.new()),
        input=input_str,
        canonical_url=canonical_url,
        host=host,
        resolved_ips=list(ips),
        ports=list(ports),
        scheme=scheme,
        port=main_port,
    )
