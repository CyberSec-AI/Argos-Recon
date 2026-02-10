from __future__ import annotations
import time
import ssl
import socket
import ulid
from urllib.parse import urlparse
from app.schemas.types import TLSArtifactV1, TargetV1
from app.core.config import TLS_TIMEOUT

async def fetch_tls_facts(target: TargetV1) -> TLSArtifactV1:
    """Récupère les infos TLS de base pour une TargetV1."""
    
    t0 = time.perf_counter()
    hostname = target.host
    port = target.port if target.port else 443
    
    artifact = TLSArtifactV1(
        tls_id=str(ulid.new()),
        target_id=target.target_id,
        observed_host=hostname,
        ip="",
        port=port
    )
    
    # Si IPs déjà résolues, on prend la première, sinon fallback host
    target_ip = target.resolved_ips[0] if target.resolved_ips else hostname
    artifact.ip = target_ip

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        conn = context.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=hostname,
        )
        conn.settimeout(TLS_TIMEOUT)
        
        try:
            conn.connect((target_ip, port))
            cert = conn.getpeercert(binary_form=True) # Non-verify returns empty dict if not binary
            # Ici simplification pour l'exemple, récupération du cipher/version
            cipher = conn.cipher()
            artifact.protocol = cipher[1]
            artifact.cipher = cipher[0]
            
            # Note: Pour le parsing complet X509 (CN, SAN, Expiry), 
            # il faudrait utiliser cryptography.x509 ici. 
            # Je garde l'exemple simple pour la structure.
            
        finally:
            conn.close()

    except Exception as e:
        artifact.error = f"{type(e).__name__}: {str(e)}"

    return artifact