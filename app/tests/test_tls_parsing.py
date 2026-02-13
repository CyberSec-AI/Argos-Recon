from app.scanner.tls import _parse_ssl_date


def test_parse_ssl_date_valid():
    raw_date = "May 26 23:59:59 2026 GMT"
    expected = "2026-05-26T23:59:59+00:00"
    assert _parse_ssl_date(raw_date) == expected


def test_parse_ssl_date_none():
    # MyPy accepte désormais car la signature a été modifiée
    assert _parse_ssl_date(None) is None
