from app.scanner.tls import _parse_ssl_date


def test_parse_ssl_date_valid():
    """Vérifie le parsing du format standard OpenSSL/Python."""
    # Format typique renvoyé par getpeercert()['notAfter']
    raw_date = "May 26 23:59:59 2026 GMT"
    expected = "2026-05-26T23:59:59+00:00"

    assert _parse_ssl_date(raw_date) == expected


def test_parse_ssl_date_edge_cases():
    """Vérifie la robustesse face aux entrées vides ou invalides."""
    assert _parse_ssl_date(None) is None
    assert _parse_ssl_date("") is None
    assert _parse_ssl_date("Not a date") is None
    # Format sans GMT (si jamais) -> Doit échouer proprement (None) ou être géré si vous changez la logique
    assert _parse_ssl_date("May 26 2026") is None


if __name__ == "__main__":
    # Permet d'exécuter ce fichier directement
    # python tests/test_tls_parsing.py
    try:
        test_parse_ssl_date_valid()
        test_parse_ssl_date_edge_cases()
        print("✅ Tests TLS Date Parsing : PASS")
    except AssertionError as e:
        print(f"❌ Tests TLS Date Parsing : FAIL ({e})")
