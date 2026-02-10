from unittest.mock import AsyncMock, patch

import httpx
import pytest

from app.scanner.http import _fetch_single
from app.schemas.types import HTTPRequestArtifactV1, TargetV1, TimingsMs, TLSArtifactV1
from app.services.scan_engine import ScanEngine


@pytest.mark.asyncio
async def test_streaming_limit_compliance():
    """Vérifie le respect strict de max_bytes avec streaming HTTP."""
    max_bytes = 50
    huge_data = b"A" * 5000  # 5 KB

    # MockTransport : pire cas (tout arrive d'un coup)
    handler = httpx.MockTransport(lambda req: httpx.Response(200, content=huge_data))

    target = TargetV1(
        target_id="t1",
        input="http://t.com",
        canonical_url="http://t.com",
        host="t.com",
    )

    async with httpx.AsyncClient(transport=handler) as client:
        artifact = await _fetch_single(target, "/", max_bytes, client)

    assert artifact.response_truncated is True
    assert artifact.response_analysis_snippet is not None
    assert len(artifact.response_analysis_snippet.encode("utf-8")) <= max_bytes


@pytest.mark.asyncio
async def test_engine_probes_on_403_behavior():
    """
    Invariant critique :
    Même si la baseline HTTP est 403, l'engine DOIT lancer les probes.
    """
    engine = ScanEngine()

    baseline_art = HTTPRequestArtifactV1(
        request_id="req1",
        target_id="t",
        url="http://t.com",
        effective_url="http://t.com",
        host="t.com",
        ip="1.1.1.1",
        port=80,
        tls=False,
        method="GET",
        status_code=403,
        headers={},
        timings_ms=TimingsMs(total=10),
    )

    # IMPORTANT: on renvoie un vrai TLSArtifactV1 (pas un AsyncMock)
    # pour éviter les warnings "coroutine was never awaited" dans extract_signals.
    tls_art = TLSArtifactV1(
        tls_id="tls1",
        target_id="t",
        observed_host="t.com",
        ip="1.1.1.1",
        port=443,
        cn="t.com",
        issuer_o=None,
        not_after=None,
        protocol=None,
        cipher=None,
        error=None,
        timings_ms=TimingsMs(total=5),
    )

    with (
        patch(
            "app.services.scan_engine.normalize_target", new_callable=AsyncMock
        ) as mock_norm,
        patch(
            "app.services.scan_engine.collect_dns_async", new_callable=AsyncMock
        ) as mock_dns,
        patch(
            "app.services.scan_engine.fetch_tls_facts", new_callable=AsyncMock
        ) as mock_tls,
        patch(
            "app.services.scan_engine.fetch_http_baseline", new_callable=AsyncMock
        ) as mock_baseline,
        patch(
            "app.services.scan_engine.probe_paths", new_callable=AsyncMock
        ) as mock_probe,
    ):
        mock_norm.return_value = TargetV1(
            target_id="t",
            input="http://t.com",
            canonical_url="http://t.com",
            host="t.com",
            resolved_ips=["1.1.1.1"],
        )
        mock_dns.return_value = None
        mock_tls.return_value = tls_art
        mock_baseline.return_value = baseline_art
        mock_probe.return_value = []

        await engine.run("http://t.com")

        assert mock_probe.await_count == 1


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
