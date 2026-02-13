from __future__ import annotations

import asyncio
import time

import dns.resolver
import ulid

from app.core.config import DNS_TIMEOUT
from app.schemas.types import DNSArtifactV1, TargetV1, TimingsMs


def _get_registrable_domain(hostname: str) -> str:
    parts = hostname.split(".")
    return ".".join(parts[-2:]) if len(parts) > 2 else hostname


def _fetch_dns_records_sync(target: TargetV1) -> DNSArtifactV1:
    domain = target.host
    root_domain = _get_registrable_domain(domain)
    t0 = time.perf_counter()
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT

    artifact = DNSArtifactV1(
        dns_id=str(ulid.new()),
        target_id=target.target_id,
        domain=domain,
        a=list(set(target.resolved_ips)),
        registrable_domain_method="naive",
        timings_ms=TimingsMs(),
    )

    query_errors: list[str] = []

    def query(name: str, rtype: str) -> list[str]:
        try:
            answers = resolver.resolve(name, rtype)
            return [r.to_text().strip('"') for r in answers]
        except Exception:
            # Tagging pour le playbook (Bug B / Point 1)
            query_errors.append(f"{rtype}@{name}")
            return []

    artifact.aaaa = query(domain, "AAAA")
    artifact.mx = query(domain, "MX")
    artifact.ns = query(domain, "NS")

    # SPF/TXT avec Fallback
    artifact.txt = query(domain, "TXT")
    artifact.domain_checked_for_email_auth = domain

    if not any("v=spf1" in s.lower() for s in artifact.txt) and root_domain != domain:
        root_txt = query(root_domain, "TXT")
        if any("v=spf1" in s.lower() for s in root_txt):
            artifact.txt = list(set(artifact.txt + root_txt))
            artifact.domain_checked_for_email_auth = root_domain

    artifact.dmarc = query(f"_dmarc.{domain}", "TXT")
    if not artifact.dmarc and root_domain != domain:
        artifact.dmarc = query(f"_dmarc.{root_domain}", "TXT")
        if artifact.dmarc:
            artifact.domain_checked_for_email_auth = root_domain

    cnames = query(domain, "CNAME")
    if cnames:
        artifact.cname = cnames[0].rstrip(".")

    artifact.warnings = query_errors
    if query_errors and not (
        artifact.aaaa or artifact.mx or artifact.ns or artifact.txt or artifact.dmarc
    ):
        artifact.error = f"DNS_FAILURE: {len(query_errors)} queries failed"

    artifact.timings_ms.total = int((time.perf_counter() - t0) * 1000)
    return artifact


async def collect_dns_async(target: TargetV1) -> DNSArtifactV1:
    return await asyncio.to_thread(_fetch_dns_records_sync, target)
