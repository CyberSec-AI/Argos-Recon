from __future__ import annotations

import time
import dns.resolver
# SUPPRIMÉ : import dns.exception (inutile)
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

    # Helper interne
    def safe_query_name(name: str, qtype: str) -> list[str]:
        try:
            answers = resolver.resolve(name, qtype)
            results = []
            for r in answers:
                if qtype == "TXT":
                    if hasattr(r, 'strings'):
                        txt_val = b"".join(r.strings).decode("utf-8", errors="replace")
                        results.append(txt_val)
                    else:
                        results.append(r.to_text().strip('"'))
                else:
                    results.append(r.to_text())
            return results
        
        # Cas "Normal" : Le domaine existe mais pas ce record
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.YXDOMAIN):
            return []
        
        # Cas "Erreur Technique" : Timeout ou Serveur cassé
        # CORRECTION : On signale l'erreur pour éviter que PB3 croie que c'est vide
        except (dns.resolver.Timeout, dns.resolver.NoNameservers) as e:
            if not artifact.error:
                artifact.error = f"dns_error:{type(e).__name__}"
            return []
            
        except Exception as e:
            if not artifact.error:
                artifact.error = f"dns_unexpected:{type(e).__name__}"
            return []

    # Wrapper
    def safe_query(qtype: str) -> list[str]:
        return safe_query_name(domain, qtype)

    try:
        artifact.a = safe_query('A')
        artifact.aaaa = safe_query('AAAA')
        artifact.mx = safe_query('MX')
        artifact.ns = safe_query('NS')
        artifact.txt = safe_query('TXT')
        
        artifact.dmarc = safe_query_name(f"_dmarc.{domain}", "TXT")
        
        soa = safe_query('SOA')
        if soa: artifact.soa = soa[0]
        
        cname = safe_query('CNAME')
        if cname: artifact.cname = cname[0]

    except Exception as e:
        artifact.error = f"dns_global_failure:{type(e).__name__}"

    duration_ms = int((time.perf_counter() - t0) * 1000)
    artifact.timings_ms = duration_ms

    return artifact