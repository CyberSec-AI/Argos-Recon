from __future__ import annotations

import asyncio
import hashlib
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Optional

import ulid

from app.core.config import TLS_TIMEOUT
from app.schemas.types import TargetV1, TimingsMs, TLSArtifactV1


def parse_ssl_date(date_str: Optional[str]) -> Optional[str]:
    """Parse une date SSL en format ISO."""
    if not date_str:
        return None
    try:
        dt = datetime.strptime(date_str, "%b %d %H:%M:%S %Y GMT")
        return dt.replace(tzinfo=timezone.utc).isoformat()
    except (ValueError, TypeError):
        return None


def _fetch_tls_sync(target: TargetV1) -> TLSArtifactV1:
    t0 = time.perf_counter()
    hostname = target.host
    port = target.port or 443
    target_ip = target.resolved_ips[0] if target.resolved_ips else hostname

    artifact = TLSArtifactV1(
        tls_id=str(ulid.new()),
        target_id=target.target_id,
        observed_host=hostname,
        ip=target_ip,
        port=port,
        timings_ms=TimingsMs(),
    )

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        t_conn = time.perf_counter()
        with socket.create_connection((target_ip, port), timeout=TLS_TIMEOUT) as raw_sock:
            artifact.timings_ms.connect = int((time.perf_counter() - t_conn) * 1000)

            t_hs = time.perf_counter()
            with context.wrap_socket(raw_sock, server_hostname=hostname) as conn:
                artifact.timings_ms.handshake = int((time.perf_counter() - t_hs) * 1000)
                artifact.protocol = conn.version()
                cipher_info = conn.cipher()
                if cipher_info:
                    artifact.cipher = cipher_info[0]

                der_cert = conn.getpeercert(binary_form=True)
                if der_cert:
                    artifact.peer_cert_sha256 = hashlib.sha256(der_cert).hexdigest()
    except Exception as e:
        artifact.error = str(e)

    artifact.timings_ms.total = int((time.perf_counter() - t0) * 1000)
    return artifact


async def fetch_tls_facts(target: TargetV1) -> TLSArtifactV1:
    return await asyncio.to_thread(_fetch_tls_sync, target)
