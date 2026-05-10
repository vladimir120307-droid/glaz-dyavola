"""Тесты sweep-модуля (только локальные проверки структуры)."""
from __future__ import annotations

from glaz.modules.subdomains.sweep import COMMON_PREFIXES


def test_common_prefixes_count() -> None:
    assert len(COMMON_PREFIXES) >= 100


def test_common_prefixes_includes_essentials() -> None:
    for p in ("www", "mail", "api", "admin", "dev", "staging", "vpn", "git"):
        assert p in COMMON_PREFIXES


def test_common_prefixes_no_duplicates() -> None:
    assert len(COMMON_PREFIXES) == len(set(COMMON_PREFIXES))
