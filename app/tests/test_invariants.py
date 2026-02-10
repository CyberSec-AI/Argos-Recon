from unittest.mock import AsyncMock, patch

import httpx
import pytest

from app.scanner.http import _fetch_single
from app.schemas.types import HTTPRequestArtifactV1, TargetV1
from app.services.scan_engine import ScanEngine


@pytest.mark.asyncio
async def test_streaming_limit_compliance():
    """Vérifie le respect strict de max_bytes avec streaming."""
    max_bytes = 50
    huge_data = b"A" * 5000

    # MockTransport qui simule une réponse streamée (tout d'un coup, pire cas)
    handler = httpx.MockTransport(lambda req: httpx.Response(200, content=huge_data))

    target = TargetV1(
        target_id="t1", input="http://t.com", canonical_url="http://t.com", host="t.com"
    )

    async with httpx.AsyncClient(transport=handler) as client:
        artifact = await _fetch_single(target, "/", max_bytes, client)

    assert artifact.response_truncated is True
    assert artifact.response_analysis_snippet is not None
    assert len(artifact.response_analysis_snippet.encode("utf-8")) <= max_bytes


@pytest.mark.asyncio
async def test_engine_probes_on_403_behavior():
    """Vérifie que l'engine probe même si la baseline est 403."""
    engine = ScanEngine()

    baseline_art = HTTPRequestArtifactV1(
        request_id="1",
        target_id="t",
        url="http://x",
        method="GET",
        status_code=403,
        error=None,
    )

    with patch(
        "app.services.scan_engine.normalize_target", new_callable=AsyncMock
    ) as mock_norm, patch(
        "app.services.scan_engine.collect_dns_async", new_callable=AsyncMock
    ) as _, patch(
        "app.services.scan_engine.fetch_tls_facts", new_callable=AsyncMock
    ) as _, patch(
        "app.services.scan_engine.fetch_http_baseline", new_callable=AsyncMock
    ) as mock_baseline, patch(
        "app.services.scan_engine.probe_paths", new_callable=AsyncMock
    ) as mock_probe:

        mock_norm.return_value = TargetV1(
            target_id="t",
            input="http://t.com",
            canonical_url="http://t.com",
            host="t.com",
            resolved_ips=["1.1.1.1"],
        )
        mock_baseline.return_value = baseline_art
        mock_probe.return_value = []

        await engine.run("http://test.com")

        # Le test valide l'appel de la fonction probe_paths
        assert mock_probe.await_count == 1


if __name__ == "__main__":
    print("Run `pytest tests/test_invariants.py`")
