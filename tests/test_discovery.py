"""Тесты discovery-слоя — только локальная логика (без сети)."""
from __future__ import annotations

from glaz.modules.discovery.tld import COMMON_TLDS
from glaz.modules.discovery.whois_rdap import RDAP_BASE, WHOIS_SERVERS, _tld


def test_tld_extract() -> None:
    assert _tld("example.com") == "com"
    assert _tld("foo.example.org.") == "org"
    assert _tld("xn--p1ai") == "xn--p1ai"


def test_rdap_has_main_tlds() -> None:
    for tld in ("com", "net", "org", "ru", "io"):
        assert tld in RDAP_BASE


def test_whois_has_main_tlds() -> None:
    for tld in ("com", "net", "ru", "uk"):
        assert tld in WHOIS_SERVERS


def test_common_tlds_includes_ru() -> None:
    assert "ru" in COMMON_TLDS
    assert "com" in COMMON_TLDS
    assert "su" in COMMON_TLDS
