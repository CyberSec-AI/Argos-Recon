from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import List, Tuple, Union, cast

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
    """
    Orchestrateur Industriel Argos-Recon.
    Gère le pipeline complet : Normalisation -> Acquisition -> Intelligence -> Reporting.
    """

    def __init__(self) -> None:
        # Chargement initial des ressources de connaissance
        self.probes = cast(List[str], load_json_list("probes.json"))
        self.cms_rules = load_cms_rules()
        self.cve_db = load_cve_db()

        # Fallback de sécurité pour les sondes
        if not self.probes:
            self.probes = ["/robots.txt", "/sitemap.xml", "/wp-login.php"]

    async def run(self, url: str) -> dict:
        """
        Point d'entrée principal pour l'analyse d'une cible.
        """
        run_id = str(ulid.new())

        # 1. Normalisation (Extraction host, port, scheme)
        try:
            target = await normalize_target(url)
        except Exception as e:
            return {
                "error": f"Normalization failed: {str(e)}",
                "status": "failed",
                "run_id": run_id,
            }

        ctx = ScanContext(run_id=run_id, target=target)
        scan_semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

        # Config des timeouts granulaires (Phase A.2)
        timeout_config = httpx.Timeout(
            connect=HTTP_TIMEOUT_CONNECT,
            read=HTTP_TIMEOUT_READ,
            write=HTTP_TIMEOUT_WRITE,
            pool=HTTP_TIMEOUT_POOL,
        )

        try:
            # 2. Acquisition DNS (Indépendante)
            try:
                ctx.dns = await collect_dns_async(ctx.target)
            except Exception as e:
                ctx.add_error("dns", "collection_failed", str(e))

            # 3. Acquisition TLS & HTTP (Client unique orchestré)
            async with httpx.AsyncClient(
                verify=False,  # nosec B501: Requis pour le scan TLS promiscuous
                timeout=timeout_config,
                follow_redirects=True,
            ) as http_client:
                # Exécution parallèle TLS + Baseline HTTP (Unpacking sécurisé MyPy)
                # On force return_exceptions=True pour ne pas crasher le moteur si un site est instable
                results: Tuple[
                    Union[TLSArtifactV1, Exception], Union[HTTPRequestArtifactV1, Exception]
                ] = await asyncio.gather(
                    fetch_tls_facts(ctx.target),
                    fetch_http_baseline(ctx.target, RESPONSE_RAW_MAX_BYTES, http_client),
                    return_exceptions=True,
                )  # type: ignore

                tls_res, http_res = results

                # Dispatching TLS
                if isinstance(tls_res, TLSArtifactV1):
                    ctx.tls = tls_res
                elif isinstance(tls_res, Exception):
                    ctx.add_error("tls", "failed", str(tls_res))

                # Dispatching HTTP Baseline
                http_baseline_ok = False
                if isinstance(http_res, HTTPRequestArtifactV1):
                    ctx.http.append(http_res)
                    http_baseline_ok = not http_res.error
                elif isinstance(http_res, Exception):
                    ctx.add_error("http", "baseline_failed", str(http_res))

                # 4. Probing (Si la cible est joignable)
                if http_baseline_ok or (ctx.dns and ctx.dns.a):
                    try:
                        probe_list = self.probes[: MAX_HTTP_REQUESTS_PER_SCAN - 1]
                        probe_results = await probe_paths(
                            ctx.target,
                            probe_list,
                            RESPONSE_RAW_MAX_BYTES,
                            http_client,
                            scan_semaphore,
                        )
                        ctx.http.extend(probe_results)
                    except Exception as e:
                        ctx.add_error("http", "probing_failed", str(e))

                # 5. Détection CMS & Extraction de Signaux
                try:
                    ctx.cms = detect_cms(ctx.target, ctx.http, rules=self.cms_rules)
                except Exception as e:
                    ctx.add_error("cms", "failed", str(e))

                ctx.signals = extract_signals(ctx.tls, ctx.http)

                # 6. Intelligence (Exécution des Playbooks de corrélation)
                self._apply_playbooks(ctx)

        except Exception as e:
            ctx.add_error("engine", "critical_failure", str(e))

        # 7. Finalisation du rapport
        finished_at = datetime.now(timezone.utc)
        duration_ms = int((finished_at - ctx.started_at).total_seconds() * 1000)

        return build_report_from_context(ctx, finished_at, duration_ms).model_dump()

    def _apply_playbooks(self, ctx: ScanContext) -> None:
        """
        Applique la logique métier pour générer des Findings à partir des Signaux.
        """
        # Playbook 1 : Faiblesses TLS (Certificat, Cipher, Protocol)
        if ctx.tls:
            f1 = evaluate_pb1(ctx.signals, ctx.target, ctx.tls.tls_id, str(ulid.new()))
            if f1:
                ctx.findings.append(f1)

        # Playbook 2 : Analyse des Headers HTTP (HSTS, CSP, etc.)
        if ctx.http:
            f2 = evaluate_pb2(ctx.signals, ctx.target, ctx.http)
            if f2:
                ctx.findings.append(f2)

        # Playbook 3 & 4 : DNS & Takeover Intelligence
        if ctx.dns:
            f3 = evaluate_pb3(dns=ctx.dns, target=ctx.target)
            if f3:
                ctx.findings.append(f3)

            f4 = evaluate_pb4(ctx.dns, ctx.target, ctx.http)
            if f4:
                ctx.findings.append(f4)

        # Playbook 5 : Spécificités WordPress & CVE
        if ctx.cms and ctx.cms.detected_cms == "wordpress":
            f5_list = evaluate_pb5(ctx.cms, ctx.target, ctx.http, self.cve_db)
            if f5_list:
                ctx.findings.extend(f5_list)
