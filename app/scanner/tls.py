from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any, Optional, cast

import ulid

from app.core.config import TLS_TIMEOUT
from app.schemas.types import TargetV1, TimingsMs, TLSArtifactV1


def _is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _parse_ssl_date(date_str: Optional[str]) -> Optional[str]:
    if not date_str:
        return None
    try:
        dt = datetime.strptime(date_str, "%b %d %H:%M:%S %Y GMT")
        return dt.replace(tzinfo=timezone.utc).isoformat()
    except (ValueError, TypeError):
        return None


def _extract_x509_field(cert_dict: dict[str, Any], section: str, attr_name: str) -> Optional[str]:
    try:
        rdns = cert_dict.get(section, ())
        for rdn in rdns:
            for key, value in rdn:
                if key == attr_name:
                    return str(value)
    except Exception:
        pass
    return None


def _fetch_tls_sync(target: TargetV1) -> TLSArtifactV1:
    t0 = time.perf_counter()
    hostname = target.host
    port = target.ports[0] if target.ports else 443

    artifact = TLSArtifactV1(
        tls_id=str(ulid.new()),
        target_id=target.target_id,
        observed_host=hostname,
        ip="",
        port=port,
        timings_ms=TimingsMs(),
    )

    target_ip = target.resolved_ips[0] if target.resolved_ips else hostname
    artifact.ip = target_ip
    server_name = None if _is_ip_address(hostname) else hostname

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((target_ip, port), timeout=TLS_TIMEOUT) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=server_name) as conn:
                cipher = conn.cipher()
                if cipher:
                    artifact.protocol = str(cipher[1])
                    artifact.cipher = str(cipher[0])

                cert = conn.getpeercert()
                if cert:
                    # On cast le certificat en dictionnaire pour MyPy
                    cert_dict = cast(dict[str, Any], cert)
                    artifact.cn = _extract_x509_field(cert_dict, "subject", "commonName")
                    artifact.issuer_o = _extract_x509_field(cert_dict, "issuer", "organizationName")

                    raw_not_after = cert_dict.get("notAfter")
                    if isinstance(raw_not_after, str):
                        artifact.not_after = _parse_ssl_date(raw_not_after)
    except Exception as e:
        artifact.error = f"{type(e).__name__}: {str(e)}"

    duration = int((time.perf_counter() - t0) * 1000)
    artifact.timings_ms = TimingsMs(total=duration)

    return artifact


async def fetch_tls_facts(target: TargetV1) -> TLSArtifactV1:
    return await asyncio.to_thread(_fetch_tls_sync, target)
