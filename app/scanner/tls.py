# app/scanner/tls.py
from __future__ import annotations

import asyncio
import hashlib
import socket
import ssl
import ulid
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID

from app.schemas.types import TLSArtifactV1


def _fetch_tls_sync(host: str, ip: str, port: int, timeout: float) -> dict:
    """
    Exécute un handshake TLS permissif et extrait :
    - Les détails du certificat (via cryptography)
    - La configuration de session (Protocol, Cipher, ALPN)
    - Les erreurs de connexion
    """
    # Configuration permissif (Promiscuous mode)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    # On supporte ALPN pour voir si le serveur parle HTTP/2
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    
    # On évite la compression (sécurité) mais on reste compatible
    ctx.options |= ssl.OP_NO_COMPRESSION

    result = {
        "cn": None,
        "san": [],
        "issuer_dn": None,
        "serial_number": None,
        "self_signed": False,
        "not_before": None,
        "not_after": None,
        "hash": None,
        "protocol": None,
        "cipher": None,
        "alpn": None,
        "error": None
    }

    try:
        # Connexion TCP
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            # Handshake TLS
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                
                # 1. Extraction des métadonnées de session TLS
                result["protocol"] = ssock.version()  # ex: TLSv1.3
                cipher_info = ssock.cipher()
                if cipher_info:
                    result["cipher"] = cipher_info[0]  # Nom du cipher
                result["alpn"] = ssock.selected_alpn_protocol()

                # 2. Récupération du certificat brut (DER)
                der_data = ssock.getpeercert(binary_form=True)
                
                if not der_data:
                    result["error"] = "empty_cert_received"
                    return result

                # 3. Parsing Cryptography
                cert = x509.load_der_x509_certificate(der_data)
                
                # Fingerprint
                sha = hashlib.sha256(der_data).hexdigest()
                result["hash"] = f"sha256:{sha}"
                
                # Serial Number
                result["serial_number"] = str(cert.serial_number)

                # Common Name (CN)
                try:
                    cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                    if cn_attr:
                        result["cn"] = cn_attr[0].value
                except Exception:
                    pass

                # SANs (DNS + IP) - Correction du shadowing de variable 'ip'
                san_list = []
                try:
                    ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    
                    # DNS Names
                    dns_names = ext.value.get_values_for_type(x509.DNSName)
                    san_list.extend(dns_names)
                    
                    # IP Addresses (Correction ici : on utilise ip_addr pour ne pas écraser l'argument ip)
                    ip_addresses = ext.value.get_values_for_type(x509.IPAddress)
                    san_list.extend([str(ip_addr) for ip_addr in ip_addresses])
                except x509.ExtensionNotFound:
                    pass
                except Exception:
                    pass
                
                result["san"] = san_list

                # Issuer & Self-Signed Check
                try:
                    result["issuer_dn"] = cert.issuer.rfc4514_string()
                    # Comparaison DN simple (suffisant pour recon)
                    result["self_signed"] = (cert.subject == cert.issuer)
                except Exception:
                    pass

                # Dates ISO 8601
                try:
                    nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
                    na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
                    if nb: result["not_before"] = nb.isoformat().replace("+00:00", "Z")
                    if na: result["not_after"] = na.isoformat().replace("+00:00", "Z")
                except Exception:
                    pass

    except socket.timeout:
        result["error"] = "timeout"
    except ConnectionRefusedError:
        result["error"] = "connection_refused"
    except ssl.SSLError as e:
        result["error"] = f"ssl_error:{e.reason if hasattr(e, 'reason') else 'unknown'}"
    except Exception as e:
        result["error"] = f"scan_error:{type(e).__name__}"

    return result


async def fetch_tls_facts(target: dict) -> TLSArtifactV1:
    host = target["host"]
    ip = target["resolved_ips"][0]
    port = target["port"]
    
    # Harmonisation du timeout : on utilise celui défini dans les guardrails ou une valeur cohérente
    # Ici hardcodé à 4.0s pour correspondre à ton guardrail 'tls': 4000
    timeout = 4.0 

    data = await asyncio.to_thread(_fetch_tls_sync, host, ip, port, timeout)

    return TLSArtifactV1(
        tls_id=str(ulid.new()),
        target_id=target["target_id"],
        observed_host=host,
        ip=ip,
        port=port,
        cn=data.get("cn"),
        san=data.get("san", []),
        issuer_dn=data.get("issuer_dn"),
        serial_number=data.get("serial_number"),
        self_signed=data.get("self_signed", False),
        not_before=data.get("not_before"),
        not_after=data.get("not_after"),
        hash=data.get("hash"),
        protocol=data.get("protocol"),
        cipher=data.get("cipher"),
        alpn=data.get("alpn"),
        error=data.get("error")
    )