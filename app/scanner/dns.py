from __future__ import annotations
import time
import asyncio
import dns.resolver
import ulid
from app.schemas.types import DNSArtifactV1, TargetV1
from app.core.config import DNS_TIMEOUT

def _fetch_dns_records_sync(target: TargetV1) -> DNSArtifactV1:
    domain = target.host
    t0 = time.perf_counter()
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT
    
    artifact = DNSArtifactV1(
        dns_id=str(ulid.new()),
        target_id=target.target_id,
        domain=domain
    )

    def safe_query_txt(name):
        try:
            answers = resolver.resolve(name, 'TXT')
            return [r.to_text().strip('"') for r in answers]
        except Exception:
            return []

    def safe_query_cname(name):
        try:
            answers = resolver.resolve(name, 'CNAME')
            return str(answers[0].target).rstrip('.')
        except Exception:
            return None

    try:
        # TXT (SPF)
        artifact.txt = safe_query_txt(domain)
        
        # DMARC (_dmarc.domain)
        artifact.dmarc = safe_query_txt(f"_dmarc.{domain}")
        
        # CNAME
        artifact.cname = safe_query_cname(domain)

        # MX, A, etc... (tu peux ajouter les autres ici selon tes besoins)

    except Exception as e:
        artifact.error = f"dns_global_failure:{type(e).__name__}"

    artifact.timings_ms = int((time.perf_counter() - t0) * 1000)
    return artifact

async def collect_dns_async(target: TargetV1) -> DNSArtifactV1:
    return await asyncio.to_thread(_fetch_dns_records_sync, target)