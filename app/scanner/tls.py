from __future__ import annotations
import time
import ssl
import socket
import ulid
import asyncio
import ipaddress
from app.schemas.types import TLSArtifactV1, TargetV1, TimingsMs
from app.core.config import TLS_TIMEOUT

def _is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def _fetch_tls_sync(target: TargetV1) -> TLSArtifactV1:
    t0 = time.perf_counter()
    hostname = target.host
    
    if target.ports and len(target.ports) > 0:
        port = target.ports[0]
    else:
        port = 443
    
    artifact = TLSArtifactV1(
        tls_id=str(ulid.new()),
        target_id=target.target_id,
        observed_host=hostname,
        ip="",
        port=port,
        timings_ms=TimingsMs() # Init vide
    )
    
    target_ip = target.resolved_ips[0] if target.resolved_ips else hostname
    artifact.ip = target_ip
    
    server_name = None if _is_ip_address(hostname) else hostname

    raw_sock = None
    conn = None

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        raw_sock = socket.create_connection((target_ip, port), timeout=TLS_TIMEOUT)
        conn = context.wrap_socket(raw_sock, server_hostname=server_name)
        
        cipher = conn.cipher()
        if cipher:
            artifact.protocol = cipher[1]
            artifact.cipher = cipher[0]

    except Exception as e:
        artifact.error = f"{type(e).__name__}: {str(e)}"
    
    finally:
        if conn:
            try: conn.close()
            except: pass
        elif raw_sock:
            try: raw_sock.close()
            except: pass
    
    # CORRECTION : Assignation objet
    duration = int((time.perf_counter() - t0) * 1000)
    artifact.timings_ms = TimingsMs(total=duration)
    
    return artifact

async def fetch_tls_facts(target: TargetV1) -> TLSArtifactV1:
    return await asyncio.to_thread(_fetch_tls_sync, target)