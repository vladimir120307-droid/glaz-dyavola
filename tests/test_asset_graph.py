from glaz.core.asset_graph import Asset, AssetGraph, AssetType, Edge


def test_asset_id_format() -> None:
    aid = Asset.make_id(AssetType.DOMAIN, "Example.COM")
    assert aid == "domain:example.com"


def test_add_asset_idempotent() -> None:
    g = AssetGraph()
    a1 = Asset(id="domain:foo.com", type=AssetType.DOMAIN, value="foo.com",
               attributes={"a": 1}, tags=["t1"])
    a2 = Asset(id="domain:foo.com", type=AssetType.DOMAIN, value="foo.com",
               attributes={"b": 2}, tags=["t2"])
    g.add_asset(a1)
    g.add_asset(a2)
    assert len(g) == 1
    merged = g.get("domain:foo.com")
    assert merged is not None
    assert merged.attributes == {"a": 1, "b": 2}
    assert set(merged.tags) == {"t1", "t2"}


def test_edge_creates_endpoints() -> None:
    g = AssetGraph()
    g.add_edge(Edge(subject="domain:foo.com", relation="resolves_to", object="ip:1.2.3.4"))
    assert g.get("domain:foo.com") is not None
    assert g.get("ip:1.2.3.4") is not None
    assert g.get("ip:1.2.3.4").type == AssetType.IP


def test_neighbors() -> None:
    g = AssetGraph()
    g.add_edge(Edge(subject="domain:a.com", relation="resolves_to", object="ip:1.1.1.1"))
    g.add_edge(Edge(subject="domain:a.com", relation="resolves_to", object="ip:2.2.2.2"))
    nbrs = g.neighbors("domain:a.com")
    assert len(nbrs) == 2


def test_to_dict_stats() -> None:
    g = AssetGraph()
    g.add_asset(Asset(id="domain:a.com", type=AssetType.DOMAIN, value="a.com"))
    g.add_asset(Asset(id="ip:1.1.1.1", type=AssetType.IP, value="1.1.1.1"))
    d = g.to_dict()
    assert d["stats"]["assets_total"] == 2
    assert d["stats"]["by_type"]["domain"] == 1
    assert d["stats"]["by_type"]["ip"] == 1
