from __future__ import annotations
import ulid
import asyncio
from datetime import datetime, timezone

from app.core.config import MAX_HTTP_REQUESTS_PER_SCAN, RESPONSE_RAW_MAX_BYTES
from app.core.normalize import normalize_target
from app.core.data_loader import load_json_list, load_cms_rules
from app.schemas.context import ScanContext
from app.core.runreport import build_report_from_context

from app.scanner.dns import collect_dns_async
from app.scanner.tls import fetch_tls_facts
from app.scanner.http import fetch_http_baseline, probe_paths
from app.scanner.cms import detect_cms

from app.core.signals import extract_signals
from app.core.playbooks.pb1 import evaluate_pb1
from app.core.playbooks.pb2 import evaluate_pb2
from app.core.playbooks.pb3 import evaluate_pb3
from app.core.playbooks.pb4 import evaluate_pb4
from app.core.playbooks.pb5_wordpress import evaluate_pb5

class ScanEngine:
    def __init__(self):
        self.probes = load_json_list("probes.json")
        self.cms_rules = load_cms_rules()
        if not isinstance(self.cms_rules, list): self.cms_rules = []
        if not self.probes:
            self.probes = ["/robots.txt", "/sitemap.xml", "/wp-login.php", "/xmlrpc.php"]

    async def run(self, url: str) -> dict:
        run_id = str(ulid.new())
        
        try:
            target = await normalize_target(url)
        except Exception as e:
            return {"error": str(e), "status": "failed"}

        ctx = ScanContext(run_id=run_id, target=target)
        ctx.metadata["limits"] = {
            "max_requests": MAX_HTTP_REQUESTS_PER_SCAN,
            "max_bytes": RESPONSE_RAW_MAX_BYTES
        }

        try:
            try:
                ctx.dns = await collect_dns_async(ctx.target)
            except Exception as e:
                ctx.add_error("dns", "collection_failed", str(e))

            results = await asyncio.gather(
                fetch_tls_facts(ctx.target),
                fetch_http_baseline(ctx.target, response_raw_max_bytes=RESPONSE_RAW_MAX_BYTES),
                return_exceptions=True
            )
            tls_res, http_res = results

            if isinstance(tls_res, Exception): ctx.add_error("tls", "failed", str(tls_res))
            else: ctx.tls = tls_res

            if isinstance(http_res, Exception): ctx.add_error("http", "failed", str(http_res)); http_baseline = None
            else: ctx.http.append(http_res); http_baseline = http_res

            if http_baseline:
                budget = MAX_HTTP_REQUESTS_PER_SCAN - 1
                safe_probes = self.probes[:budget]
                if safe_probes:
                    try:
                        res = await probe_paths(ctx.target, safe_probes, response_raw_max_bytes=RESPONSE_RAW_MAX_BYTES)
                        ctx.http.extend(res)
                    except Exception as e: ctx.add_error("http", "probing_failed", str(e))

            try:
                ctx.cms = detect_cms(ctx.target, ctx.http, rules=self.cms_rules)
            except Exception as e: ctx.add_error("cms", "failed", str(e))

            ctx.signals = extract_signals(ctx.tls, ctx.http)
            
            if ctx.tls and http_baseline:
                f1 = evaluate_pb1(ctx.signals, ctx.target, ctx.tls.tls_id, http_baseline.request_id)
                if f1: ctx.findings.append(f1)
            
            f2 = evaluate_pb2(ctx.signals, ctx.target, ctx.http)
            if f2: ctx.findings.append(f2)
            
            if ctx.dns:
                f3 = evaluate_pb3(ctx.dns, ctx.target)
                if f3: ctx.findings.append(f3)
                f4 = evaluate_pb4(ctx.dns, ctx.target, ctx.http)
                if f4: ctx.findings.append(f4)
            
            if ctx.cms:
                f5 = evaluate_pb5(ctx.cms, ctx.target, ctx.http)
                if f5: ctx.findings.extend(f5)

        except Exception as e:
            import traceback; traceback.print_exc()
            ctx.add_error("engine", "critical_failure", str(e))

        finished_at = datetime.now(timezone.utc)
        duration_ms = int((finished_at - ctx.started_at).total_seconds() * 1000)
        return build_report_from_context(ctx, finished_at, duration_ms).model_dump()