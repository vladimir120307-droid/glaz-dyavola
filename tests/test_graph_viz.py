"""Тесты визуализации графа: Mermaid + DOT генерация."""
from __future__ import annotations

from glaz.core.asset_graph import Asset, AssetGraph, AssetType, Edge
from glaz.core.graph_viz import _safe_id, _truncate, to_dot, to_mermaid


def _sample_graph() -> AssetGraph:
    g = AssetGraph()
    g.add_asset(Asset(id="domain:example.com", type=AssetType.DOMAIN, value="example.com"))
    g.add_asset(Asset(id="ip:1.1.1.1", type=AssetType.IP, value="1.1.1.1"))
    g.add_asset(Asset(id="secret:abc", type=AssetType.SECRET, value="abc"))
    g.add_edge(Edge(subject="domain:example.com", relation="resolves_to", object="ip:1.1.1.1"))
    g.add_edge(Edge(subject="secret:abc", relation="found_in", object="domain:example.com"))
    return g


def test_safe_id() -> None:
    assert _safe_id("domain:example.com") == "domain_example_com"
    assert _safe_id("ip:1.1.1.1") == "ip_1_1_1_1"


def test_truncate() -> None:
    assert _truncate("short") == "short"
    assert _truncate("a" * 100, n=10).endswith("…")
    assert len(_truncate("a" * 100, n=10)) == 10


def test_mermaid_structure() -> None:
    g = _sample_graph()
    m = to_mermaid(g)
    assert m.startswith("flowchart LR")
    assert "domain_example_com" in m
    assert "ip_1_1_1_1" in m
    assert "resolves_to" in m
    assert "found_in" in m


def test_mermaid_max_nodes_truncation() -> None:
    g = AssetGraph()
    for i in range(200):
        g.add_asset(Asset(id=f"domain:test{i}.com", type=AssetType.DOMAIN, value=f"test{i}.com"))
    m = to_mermaid(g, max_nodes=50)
    # Считаем именно node-определения (строки с `["..."]`)
    node_lines = [ln for ln in m.splitlines() if "[\"" in ln and "domain_test" in ln]
    assert len(node_lines) == 50


def test_dot_structure() -> None:
    g = _sample_graph()
    d = to_dot(g)
    assert "digraph G" in d
    assert "rankdir" in d
    assert "domain_example_com" in d
    assert "->" in d
