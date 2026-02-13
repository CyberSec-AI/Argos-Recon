from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Optional, cast

import httpx
import ulid

from app.core.config import (
    HTTP_TIMEOUT_CONNECT,
    HTTP_TIMEOUT_POOL,
    HTTP_TIMEOUT_READ,
    HTTP_TIMEOUT_WRITE,
    MAX_CONCURRENT_REQUESTS,
    MAX_HTTP_REQUESTS_PER_SCAN,
    RESPONSE_RAW_MAX_BYTES,
)
from app.core.data_loader import load_cms_rules, load_cve_db, load_json_list
from app.core.normalize import normalize_target
from app.core.playbooks.pb1 import evaluate_pb1
from app.core.playbooks.pb2 import evaluate_pb2
from app.core.playbooks.pb3 import evaluate_pb3
from app.core.playbooks.pb4 import evaluate_pb4
from app.core.playbooks.pb5_wordpress import evaluate_pb5
from app.core.runreport import build_report_from_context
from app.core.signals import extract_signals
from app.scanner.cms import detect_cms
from app.scanner.dns import collect_dns_async
from app.scanner.http import fetch_http_baseline, probe_paths
from app.scanner.tls import fetch_tls_facts
from app.schemas.context import ScanContext
from app.schemas.types import HTTPRequestArtifactV1, TLSArtifactV1


class ScanEngine:
    """Orchestrateur principal du moteur de reconnaissance Argos-Recon."""

    def __init__(self) -> None:
        self.probes: list[str] = cast(list[str], load_json_list("probes.json"))
        self.cms_rules: list[dict[str, Any]] = load_cms_rules()
        self.cve_db: list[dict[str, Any]] = load_cve_db()

        if not self.probes:
            self.probes = ["/robots.txt", "/sitemap.xml", "/wp-login.php", "/xmlrpc.php"]

    async def run(self, url: str) -> dict[str, Any]:
        """Lance un scan complet et retourne un rapport structuré."""
        run_id = str(ulid.new())

        try:
            target = await normalize_target(url)
        except Exception as e:
            return {"error": str(e), "status": "failed", "run_id": run_id}

        ctx = ScanContext(run_id=run_id, target=target)
        scan_semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

        # Configuration granulaire des Timeouts (A.2)
        timeout_config = httpx.Timeout(
            connect=HTTP_TIMEOUT_CONNECT,
            read=HTTP_TIMEOUT_READ,
            write=HTTP_TIMEOUT_WRITE,
            pool=HTTP_TIMEOUT_POOL,
        )

        try:
            # Phase 1 : DNS
            try:
                ctx.dns = await collect_dns_async(ctx.target)
            except Exception as e:
                ctx.add_error("dns", "collection_failed", str(e))

            async with httpx.AsyncClient(
                verify=False,  # nosec
                timeout=timeout_config,
                follow_redirects=True,
            ) as http_client:
                # Phase 2 : TLS & Baseline HTTP
                tls_res, http_res = await asyncio.gather(
                    fetch_tls_facts(ctx.target),
                    fetch_http_baseline(ctx.target, RESPONSE_RAW_MAX_BYTES, http_client),
                    return_exceptions=True,
                )

                if isinstance(tls_res, TLSArtifactV1):
                    ctx.tls = tls_res
                elif isinstance(tls_res, Exception):
                    ctx.add_error("tls", "failed", str(tls_res))

                http_baseline: Optional[HTTPRequestArtifactV1] = None
                if isinstance(http_res, HTTPRequestArtifactV1):
                    ctx.http.append(http_res)
                    http_baseline = http_res
                elif isinstance(http_res, Exception):
                    ctx.add_error("http", "baseline_failed", str(http_res))

                # Phase 3 : Probing (Respecte le budget et le scheduler)
                if http_baseline is not None or target.resolved_ips:
                    budget = MAX_HTTP_REQUESTS_PER_SCAN - 1
                    safe_probes = self.probes[:budget]
                    if safe_probes:
                        try:
                            results = await probe_paths(
                                ctx.target,
                                safe_probes,
                                RESPONSE_RAW_MAX_BYTES,
                                http_client,
                                scan_semaphore,
                            )
                            ctx.http.extend(results)
                        except Exception as e:
                            ctx.add_error("http", "probing_failed", str(e))

                # Phase 4 : Analyse & Intelligence
                try:
                    ctx.cms = detect_cms(ctx.target, ctx.http, rules=self.cms_rules)
                except Exception as e:
                    ctx.add_error("cms", "failed", str(e))

                ctx.signals = extract_signals(ctx.tls, ctx.http)
                self._apply_playbooks(ctx)

        except Exception as e:
            ctx.add_error("engine", "critical_failure", str(e))

        finished_at = datetime.now(timezone.utc)
        duration_ms = int((finished_at - ctx.started_at).total_seconds() * 1000)
        return build_report_from_context(ctx, finished_at, duration_ms).model_dump()

    def _apply_playbooks(self, ctx: ScanContext) -> None:
        """Exécute la suite de playbooks sur le contexte de scan."""
        if ctx.tls:
            f1 = evaluate_pb1(ctx.signals, ctx.target, ctx.tls.tls_id, str(ulid.new()))
            if f1:
                ctx.findings.append(f1)

        if ctx.http:
            f2 = evaluate_pb2(ctx.signals, ctx.target, ctx.http)
            if f2:
                ctx.findings.append(f2)

        if ctx.dns:
            f3 = evaluate_pb3(ctx.dns, ctx.target)
            if f3:
                ctx.findings.append(f3)
            f4 = evaluate_pb4(ctx.dns, ctx.target, ctx.http)
            if f4:
                ctx.findings.append(f4)

        if ctx.cms:
            f5 = evaluate_pb5(ctx.cms, ctx.target, ctx.http, self.cve_db)
            if f5:
                ctx.findings.extend(f5)
