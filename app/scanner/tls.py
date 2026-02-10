from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import time
from datetime import datetime, timezone

import ulid

from app.core.config import TLS_TIMEOUT
from app.schemas.types import TargetV1, TimingsMs, TLSArtifactV1


def _is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _parse_ssl_date(date_str: str) -> str | None:
    """Convertit 'May 26 23:59:59 2026 GMT' en ISO 8601."""
    if not date_str:
        return None
    try:
        dt = datetime.strptime(date_str, "%b %d %H:%M:%S %Y GMT")
        return dt.replace(tzinfo=timezone.utc).isoformat()
    except ValueError:
        return None


def _extract_x509_field(cert_dict: dict, section: str, attr_name: str) -> str | None:
    """Extraction robuste depuis getpeercert()."""
    try:
        rdns = cert_dict.get(section, ())
        for rdn in rdns:
            for key, value in rdn:
                if key == attr_name:
                    return value
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

    raw_sock = None
    conn = None

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        # SECURITY: Mode Reconnaissance. On veut les infos même si invalide.
        context.verify_mode = ssl.CERT_NONE

        raw_sock = socket.create_connection((target_ip, port), timeout=TLS_TIMEOUT)
        conn = context.wrap_socket(raw_sock, server_hostname=server_name)

        cipher = conn.cipher()
        if cipher:
            artifact.protocol = cipher[1]
            artifact.cipher = cipher[0]

        cert = conn.getpeercert()
        if cert:
            artifact.cn = _extract_x509_field(cert, "subject", "commonName")
            artifact.issuer_o = _extract_x509_field(cert, "issuer", "organizationName")

            raw_not_after = cert.get("notAfter")
            if raw_not_after:
                artifact.not_after = _parse_ssl_date(raw_not_after)

    except Exception as e:
        artifact.error = f"{type(e).__name__}: {str(e)}"

    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        elif raw_sock:
            try:
                raw_sock.close()
            except Exception:
                pass

    duration = int((time.perf_counter() - t0) * 1000)
    artifact.timings_ms = TimingsMs(total=duration)

    return artifact


async def fetch_tls_facts(target: TargetV1) -> TLSArtifactV1:
    return await asyncio.to_thread(_fetch_tls_sync, target)
