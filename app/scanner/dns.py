from __future__ import annotations

import time
import dns.resolver
import dns.exception
import ulid

from app.schemas.types import DNSArtifactV1

def fetch_dns_records(target: dict) -> DNSArtifactV1:
    """
    Récupère les enregistrements DNS (Sync).
    À exécuter via asyncio.to_thread().
    """
    domain = target["host"]
    t0 = time.perf_counter()
    
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0
    
    artifact = DNSArtifactV1(
        dns_id=str(ulid.new()),
        target_id=target["target_id"],
        domain=domain
    )

    def safe_query(qtype: str) -> list[str]:
        try:
            answers = resolver.resolve(domain, qtype)
            results = []
            for r in answers:
                if qtype == "TXT":
                    # Gestion propre du multi-string TXT
                    if hasattr(r, 'strings'):
                        txt_val = b"".join(r.strings).decode("utf-8", errors="replace")
                        results.append(txt_val)
                    else:
                        results.append(r.to_text().strip('"'))
                else:
                    # Pas de rstrip('.') pour garder le standard FQDN
                    results.append(r.to_text())
            return results

        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return []
        except (dns.resolver.Timeout, dns.resolver.NoNameservers):
            return []
        except Exception:
            return []

    try:
        artifact.a = safe_query('A')
        artifact.aaaa = safe_query('AAAA')
        artifact.mx = safe_query('MX')
        artifact.ns = safe_query('NS')
        artifact.txt = safe_query('TXT')
        
        soa = safe_query('SOA')
        if soa: artifact.soa = soa[0]
        
        cname = safe_query('CNAME')
        if cname: artifact.cname = cname[0]

    except Exception as e:
        artifact.error = f"dns_global_failure:{type(e).__name__}"

    duration_ms = int((time.perf_counter() - t0) * 1000)
    artifact.timings_ms = duration_ms

    return artifact