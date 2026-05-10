"""Asset graph — граф наблюдаемых активов и их связей.

Модель: узлы (Asset) + ориентированные рёбра между ними (например, домен → IP, организация → домен).
Хранится в памяти; сериализуется в JSON для отчётов.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class AssetType(str, Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    ASN = "asn"
    NETBLOCK = "netblock"
    URL = "url"
    EMAIL = "email"
    ORG = "org"          # Организация (юрлицо)
    PERSON = "person"    # Физлицо
    PHONE = "phone"
    REPOSITORY = "repository"
    CLOUD_RESOURCE = "cloud_resource"
    CERT = "cert"
    SECRET = "secret"
    TENANT = "tenant"    # Identity-провайдер тенант (Entra/Okta/...)
    FILE = "file"
    OTHER = "other"


class Asset(BaseModel):
    """Узел графа. id уникален в рамках одного AssetGraph."""

    id: str = Field(..., description="Уникальный ID, например 'domain:example.com'")
    type: AssetType
    value: str = Field(..., description="Сырое значение, e.g. 'example.com'")
    attributes: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    discovered_by: str = Field(default="manual", description="Имя модуля, обнаружившего актив")

    @classmethod
    def make_id(cls, asset_type: AssetType, value: str) -> str:
        return f"{asset_type.value}:{value.lower()}"


class Edge(BaseModel):
    """Связь двух активов: subject -[relation]-> object."""

    subject: str
    relation: str  # e.g. "resolves_to", "owned_by", "uses_idp", "leaked_at"
    object: str
    attributes: dict[str, Any] = Field(default_factory=dict)
    discovered_by: str = "manual"


class AssetGraph:
    """Простой ориентированный граф."""

    def __init__(self) -> None:
        self._assets: dict[str, Asset] = {}
        self._edges: list[Edge] = []
        self._out: dict[str, list[Edge]] = defaultdict(list)
        self._in: dict[str, list[Edge]] = defaultdict(list)

    def add_asset(self, asset: Asset) -> Asset:
        """Добавить узел. Если есть — мерджит attributes/tags."""
        existing = self._assets.get(asset.id)
        if existing is None:
            self._assets[asset.id] = asset
            return asset
        # Merge
        existing.attributes.update(asset.attributes)
        existing.tags = sorted(set(existing.tags) | set(asset.tags))
        return existing

    def add_edge(self, edge: Edge) -> None:
        # Auto-create endpoints if missing — but only as OTHER
        for ep in (edge.subject, edge.object):
            if ep not in self._assets:
                # parse "type:value" hint
                if ":" in ep:
                    t, v = ep.split(":", 1)
                    try:
                        atype = AssetType(t)
                    except ValueError:
                        atype = AssetType.OTHER
                else:
                    atype, v = AssetType.OTHER, ep
                self._assets[ep] = Asset(id=ep, type=atype, value=v, discovered_by=edge.discovered_by)
        self._edges.append(edge)
        self._out[edge.subject].append(edge)
        self._in[edge.object].append(edge)

    def get(self, asset_id: str) -> Asset | None:
        return self._assets.get(asset_id)

    def assets(self, asset_type: AssetType | None = None) -> Iterator[Asset]:
        if asset_type is None:
            yield from self._assets.values()
        else:
            for a in self._assets.values():
                if a.type == asset_type:
                    yield a

    def edges(self) -> list[Edge]:
        return list(self._edges)

    def neighbors(self, asset_id: str) -> list[Asset]:
        seen: set[str] = set()
        out: list[Asset] = []
        for e in self._out.get(asset_id, []):
            if e.object in self._assets and e.object not in seen:
                seen.add(e.object)
                out.append(self._assets[e.object])
        for e in self._in.get(asset_id, []):
            if e.subject in self._assets and e.subject not in seen:
                seen.add(e.subject)
                out.append(self._assets[e.subject])
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "assets": [a.model_dump(mode="json") for a in self._assets.values()],
            "edges": [e.model_dump(mode="json") for e in self._edges],
            "stats": {
                "assets_total": len(self._assets),
                "edges_total": len(self._edges),
                "by_type": {
                    t.value: sum(1 for a in self._assets.values() if a.type == t)
                    for t in AssetType
                    if any(a.type == t for a in self._assets.values())
                },
            },
        }

    def __len__(self) -> int:
        return len(self._assets)
