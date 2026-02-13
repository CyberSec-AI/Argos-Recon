import asyncio
import copy
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.data_loader import load_cms_rules
from app.core.normalize import normalize_target
from app.core.signals import extract_signals
from app.scanner.cms import detect_cms
from app.schemas.types import HTTPRequestArtifactV1, TargetV1, TimingsMs
from app.services.scan_engine import ScanEngine


# 1. Invariant Normalize
@pytest.mark.asyncio
async def test_barrier_normalize_target():
    t = await normalize_target("http://example.com:8080")
    assert 8080 in t.ports
    assert t.scheme == "http"
    assert t.port == 8080


# 2. Invariant Engine
@pytest.mark.asyncio
async def test_barrier_engine_no_crash():
    engine = ScanEngine()
    with patch(
        "app.services.scan_engine.normalize_target", side_effect=Exception("Critical DNS Failure")
    ):
        report = await engine.run("http://invalid.test")
        assert report["status"] == "failed"
        assert "error" in report


# 3. Invariant Signals
def test_barrier_signals_none_safe():
    sigs = extract_signals(None, [])
    assert isinstance(sigs, list)
    assert len(sigs) == 0


# 4. Invariant CMS
def test_barrier_cms_robustness():
    target = TargetV1(
        target_id="t1",
        input="x",
        canonical_url="x",
        host="x",
        resolved_ips=[],
        ports=[80],
        scheme="http",
        port=80,
    )
    http = [
        HTTPRequestArtifactV1(
            request_id="r1",
            target_id="t1",
            url="x",
            effective_url="x",
            host="x",
            ip="x",
            port=80,  # Correction Arguments obligatoires
            method="GET",
            timings_ms=TimingsMs(total=1),
        )
    ]
    bad_rules = [
        {"name": "wp", "indicators": [None, "string_invalide", {"type": "body", "content": ""}]}
    ]
    res = detect_cms(target, http, rules=bad_rules)  # type: ignore
    assert res.detected_cms == "unknown"


# 5. Invariant Loader
def test_barrier_loader_immutability():
    mock_data = [{"name": "test", "indicators": [{"type": "body", "content": "marker"}]}]

    with patch(
        "app.core.data_loader.load_json_list", side_effect=lambda _: copy.deepcopy(mock_data)
    ):
        rules1 = load_cms_rules()
        assert len(rules1) > 0
        rules1[0]["name"] = "MUTATED"

        rules2 = load_cms_rules()
        assert rules2[0]["name"] == "test"


# 6. Invariant Probe
@pytest.mark.asyncio
async def test_barrier_probe_di_logic():
    from app.scanner.http import probe_paths

    target = TargetV1(
        target_id="t",
        input="x",
        canonical_url="http://x",
        host="x",
        resolved_ips=[],
        ports=[80],
        scheme="http",
        port=80,
    )
    client = MagicMock()

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {}

    async def async_iter():
        yield b"ok"

    mock_resp.aiter_bytes = MagicMock(return_value=async_iter())

    mock_cm = AsyncMock()
    mock_cm.__aenter__.return_value = mock_resp
    client.stream.return_value = mock_cm

    res = await probe_paths(target, ["/"], 1024, client, asyncio.Semaphore(1))
    assert len(res) == 1
    assert isinstance(res[0].timings_ms, TimingsMs)
