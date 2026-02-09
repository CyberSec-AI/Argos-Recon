from __future__ import annotations

# pyright: reportMissingImports=false

import asyncio
import hashlib
import ssl
import socket

import ulid
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID

from app.schemas.types import TLSArtifactV1


def _fetch_tls(host: str, ip: str, port: int, server_name: str) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Default safe values (unknown state)
    result = {
        "cn": None,
        "san": [],
        "issuer_dn": None,
        "self_signed": False,  # unknown != self-signed
        "not_before": None,
        "not_after": None,
        "hash": None
    }

    try:
        with socket.create_connection((ip, port), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=server_name) as ssock:
                der = ssock.getpeercert(binary_form=True)

        if not der:
            return result

        cert = x509.load_der_x509_certificate(der)
        sha = hashlib.sha256(der).hexdigest()
        result["hash"] = f"sha256:{sha}"

        # CN
        try:
            cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if cn_attr:
                result["cn"] = cn_attr[0].value
        except Exception:
            pass

        # SAN
        try:
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            result["san"] = ext.value.get_values_for_type(x509.DNSName)
        except Exception:
            pass

        # Issuer + self-signed
        try:
            result["issuer_dn"] = cert.issuer.rfc4514_string()
            result["self_signed"] = (cert.subject == cert.issuer)
        except Exception:
            pass

        # Dates (compatible cryptography modernes)
        try:
            nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
            na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
            # nb/na peuvent être datetime naive; on garde ISO sans forcer TZ ici
            result["not_before"] = nb.isoformat()
            result["not_after"] = na.isoformat()
        except Exception:
            pass

    except Exception:
        # MVP: silence. En prod: logger.
        pass

    return result


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
        hash=data.get("hash"),
    )
