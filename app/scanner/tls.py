from __future__ import annotations

import asyncio
import hashlib
import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

import ulid
from app.schemas.types import TLSArtifactV1


def _parse_cert_time(x: str) -> str | None:
    # Example: 'Jun  1 12:00:00 2026 GMT'
    try:
        dt = datetime.strptime(x, "%b %d %H:%M:%S %Y %Z")
        dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")
    except Exception:
        return None


def _fetch_tls(host: str, ip: str, port: int, server_name: str) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False  # we are collecting facts, not enforcing trust
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((ip, port), timeout=4) as sock:
        with ctx.wrap_socket(sock, server_hostname=server_name) as ssock:
            cert = ssock.getpeercert()
            der = ssock.getpeercert(binary_form=True)
            sha = hashlib.sha256(der).hexdigest()

    # Extract CN
    cn = None
    for tup in cert.get("subject", []):
        for k, v in tup:
            if k.lower() == "commonname":
                cn = v

    # Extract SAN
    san = []
    for typ, name in cert.get("subjectAltName", []):
        if typ.lower() == "dns":
            san.append(name)

    issuer_dn = None
    issuer_parts = []
    for tup in cert.get("issuer", []):
        for k, v in tup:
            issuer_parts.append(f"{k}={v}")
    if issuer_parts:
        issuer_dn = ", ".join(issuer_parts)

    self_signed = (cert.get("issuer") == cert.get("subject"))

    not_before = _parse_cert_time(cert.get("notBefore", "")) if cert.get("notBefore") else None
    not_after = _parse_cert_time(cert.get("notAfter", "")) if cert.get("notAfter") else None

    return {
        "cn": cn,
        "san": san,
        "issuer_dn": issuer_dn,
        "self_signed": self_signed,
        "not_before": not_before,
        "not_after": not_after,
        "hash": f"sha256:{sha}"
    }


async def fetch_tls_facts(target: dict) -> TLSArtifactV1:
    host = target["host"]
    ip = target["resolved_ips"][0]
    port = target["port"]

    data = await asyncio.to_thread(_fetch_tls, host, ip, port, host)

    return TLSArtifactV1(
        tls_id=str(ulid.new()),
        target_id=target["target_id"],
        observed_host=host,
        ip=ip,
        port=port,
        cn=data.get("cn"),
        san=data.get("san", []),
        issuer_dn=data.get("issuer_dn"),
        self_signed=bool(data.get("self_signed", False)),
        not_before=data.get("not_before"),
        not_after=data.get("not_after"),
        hash=data.get("hash")
    )
