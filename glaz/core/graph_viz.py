"""Asset graph → Mermaid / Graphviz DOT.

Используется в HTML-отчёте и для CLI-команды `glaz visualize`.
Mermaid рендерится прямо в README/docs без js-зависимостей.
"""
from __future__ import annotations

import re

from glaz.core.asset_graph import AssetGraph, AssetType

_TYPE_STYLE: dict[AssetType, tuple[str, str]] = {
    AssetType.DOMAIN:         ("🌐", "fill:#1e293b,stroke:#475569,color:#f1f5f9"),
    AssetType.SUBDOMAIN:      ("🔗", "fill:#0f172a,stroke:#334155,color:#cbd5e1"),
    AssetType.IP:             ("📡", "fill:#1e1b4b,stroke:#312e81,color:#c7d2fe"),
    AssetType.ASN:            ("🛰", "fill:#1e1b4b,stroke:#312e81,color:#c7d2fe"),
    AssetType.NETBLOCK:       ("🛰", "fill:#1e1b4b,stroke:#312e81,color:#c7d2fe"),
    AssetType.URL:            ("🔍", "fill:#0f172a,stroke:#334155,color:#cbd5e1"),
    AssetType.EMAIL:          ("✉", "fill:#0f172a,stroke:#334155,color:#cbd5e1"),
    AssetType.ORG:            ("🏛", "fill:#7c2d12,stroke:#9a3412,color:#fed7aa"),
    AssetType.PERSON:         ("👤", "fill:#7c2d12,stroke:#9a3412,color:#fed7aa"),
    AssetType.PHONE:          ("📞", "fill:#0f172a,stroke:#334155,color:#cbd5e1"),
    AssetType.REPOSITORY:     ("📦", "fill:#0f172a,stroke:#334155,color:#cbd5e1"),
    AssetType.CLOUD_RESOURCE: ("☁", "fill:#0f172a,stroke:#334155,color:#cbd5e1"),
    AssetType.CERT:           ("🔐", "fill:#0f172a,stroke:#334155,color:#cbd5e1"),
    AssetType.SECRET:         ("🔑", "fill:#7f1d1d,stroke:#dc2626,color:#fee2e2"),
    AssetType.TENANT:         ("🪪", "fill:#1e293b,stroke:#475569,color:#f1f5f9"),
    AssetType.FILE:           ("📄", "fill:#0f172a,stroke:#334155,color:#cbd5e1"),
    AssetType.OTHER:          ("·", "fill:#0f172a,stroke:#334155,color:#cbd5e1"),
}


def _safe_id(s: str) -> str:
    """Mermaid-безопасный ID: только [A-Za-z0-9_]."""
    return re.sub(r"[^A-Za-z0-9_]", "_", s)


def _truncate(s: str, n: int = 40) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


def to_mermaid(graph: AssetGraph, *, max_nodes: int = 80) -> str:
    """Сгенерировать Mermaid flowchart-диаграмму.

    Если узлов больше `max_nodes` — оставляем самых «связных» (по степени).
    """
    assets = list(graph.assets())

    if len(assets) > max_nodes:
        # Срезаем по степени: сколько раз asset фигурирует в edges
        degree: dict[str, int] = {}
        for e in graph.edges():
            degree[e.subject] = degree.get(e.subject, 0) + 1
            degree[e.object] = degree.get(e.object, 0) + 1
        assets = sorted(assets, key=lambda a: -degree.get(a.id, 0))[:max_nodes]

    asset_set = {a.id for a in assets}

    lines: list[str] = ["flowchart LR"]
    # Узлы
    for a in assets:
        emoji, _ = _TYPE_STYLE.get(a.type, ("·", ""))
        sid = _safe_id(a.id)
        label = f"{emoji} {_truncate(a.value)}"
        lines.append(f'    {sid}["{label}"]')

    # Рёбра (только если оба конца попали в срез)
    for e in graph.edges():
        if e.subject in asset_set and e.object in asset_set:
            ssub = _safe_id(e.subject)
            sobj = _safe_id(e.object)
            lines.append(f'    {ssub} -->|{e.relation}| {sobj}')

    # Стили классов
    used_types: set[AssetType] = {a.type for a in assets}
    for t in used_types:
        emoji, style = _TYPE_STYLE.get(t, ("·", ""))
        if style:
            cls = f"type_{t.value}"
            lines.append(f"    classDef {cls} {style}")
            ids = [_safe_id(a.id) for a in assets if a.type == t]
            if ids:
                lines.append(f"    class {','.join(ids)} {cls}")

    return "\n".join(lines)


def to_dot(graph: AssetGraph) -> str:
    """Сгенерировать Graphviz DOT (для рендера через graphviz/dot)."""
    lines = ["digraph G {", '  rankdir="LR";', '  bgcolor="#0f172a";',
             '  node [style="filled,rounded", shape=box, fontcolor="#f1f5f9", fontname="Helvetica"];',
             '  edge [color="#94a3b8", fontcolor="#cbd5e1", fontname="Helvetica", fontsize=10];']
    for a in graph.assets():
        sid = _safe_id(a.id)
        emoji, _ = _TYPE_STYLE.get(a.type, ("·", ""))
        label = f"{emoji} {_truncate(a.value)}".replace('"', '\\"')
        # Цветовая палитра по типам — упрощённая
        if a.type == AssetType.SECRET:
            fill = "#7f1d1d"
        elif a.type in (AssetType.ORG, AssetType.PERSON):
            fill = "#7c2d12"
        elif a.type in (AssetType.IP, AssetType.NETBLOCK, AssetType.ASN):
            fill = "#1e1b4b"
        else:
            fill = "#1e293b"
        lines.append(f'  {sid} [label="{label}", fillcolor="{fill}"];')
    for e in graph.edges():
        ssub = _safe_id(e.subject)
        sobj = _safe_id(e.object)
        lines.append(f'  {ssub} -> {sobj} [label="{e.relation}"];')
    lines.append("}")
    return "\n".join(lines)
