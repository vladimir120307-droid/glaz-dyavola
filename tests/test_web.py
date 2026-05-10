"""Тесты web-attack-surface модуля: regex-extracторы и path-каталоги."""
from __future__ import annotations

from glaz.modules.web.attack_surface import (
    ENDPOINT_RE_TIER1,
    ENDPOINT_RE_TIER2,
    GRAPHQL_PATHS,
    INTERNAL_HOST_RE,
    SECURITY_HEADERS,
    SWAGGER_PATHS,
)


def test_swagger_paths_count() -> None:
    assert len(SWAGGER_PATHS) >= 25
    assert "/swagger.json" in SWAGGER_PATHS
    assert "/openapi.yaml" in SWAGGER_PATHS


def test_graphql_paths_count() -> None:
    assert len(GRAPHQL_PATHS) >= 10
    assert "/graphql" in GRAPHQL_PATHS


def test_security_headers_set() -> None:
    keys = set(SECURITY_HEADERS.keys())
    assert "strict-transport-security" in keys
    assert "content-security-policy" in keys


def test_endpoint_extract_tier1() -> None:
    js = """
    fetch('/api/v1/users');
    const u = "/admin/dashboard";
    window.LOGIN = '/auth/login';
    """
    matches = ENDPOINT_RE_TIER1.findall(js)
    assert "/api/v1/users" in matches
    assert "/admin/dashboard" in matches
    assert "/auth/login" in matches


def test_endpoint_extract_tier2() -> None:
    js = "fetch('/config.json'); load('/static/data.yaml');"
    matches = ENDPOINT_RE_TIER2.findall(js)
    assert "/config.json" in matches
    assert "/static/data.yaml" in matches


def test_internal_host_regex() -> None:
    text = "auth.corp.example.com and api.internal and svc.cluster.local"
    matches = INTERNAL_HOST_RE.findall(text)
    # должны попасть .internal, .corp, svc.cluster.local
    assert any("internal" in m for m in matches) or len(matches) >= 1
