"""Перечисление поддоменов через несколько источников.

Источники:
1. crt.sh (CT logs) — основной
2. AlienVault OTX
3. ThreatMiner
4. HackerTarget (rate-limited, free tier)
5. RapidDNS
6. Wayback Machine CDX (история)

Все источники не требуют API-ключей. Сортируется по уникальности и убирает
wildcard-записи (`*.example.com`).
"""
from __future__ import annotations

import asyncio
import re
from collections.abc import Awaitable, Callable

import httpx

from glaz.core.asset_graph import Asset, AssetGraph, AssetType, Edge
from glaz.utils.http import get_async_client

WILDCARD_RE = re.compile(r"^\*\.")
SUBDOMAIN_RE = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9\-_]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-_]*[a-zA-Z0-9])?)+$")


async def _src_crtsh(client: httpx.AsyncClient, domain: str) -> set[str]:
    try:
        r = await client.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=20.0)
        if r.status_code != 200:
            return set()
        data = r.json()
    except (httpx.HTTPError, ValueError):
        return set()
    out: set[str] = set()
    for entry in data:
        for nv in (entry.get("name_value") or "").split("\n"):
            nv = nv.strip().lower()
            if nv and not WILDCARD_RE.match(nv) and nv.endswith(domain.lower()):
                out.add(nv)
    return out


async def _src_otx(client: httpx.AsyncClient, domain: str) -> set[str]:
    try:
        r = await client.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            timeout=20.0,
        )
        if r.status_code != 200:
            return set()
        data = r.json()
    except (httpx.HTTPError, ValueError):
        return set()
    out: set[str] = set()
    for item in data.get("passive_dns", []):
        h = (item.get("hostname") or "").strip().lower()
        if h and h.endswith(domain.lower()) and SUBDOMAIN_RE.match(h):
            out.add(h)
    return out


async def _src_threatminer(client: httpx.AsyncClient, domain: str) -> set[str]:
    try:
        r = await client.get(
            f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5", timeout=15.0,
        )
        if r.status_code != 200:
            return set()
        data = r.json()
    except (httpx.HTTPError, ValueError):
        return set()
    return {
        s.strip().lower() for s in (data.get("results") or [])
        if isinstance(s, str) and s.endswith(domain.lower())
    }


async def _src_hackertarget(client: httpx.AsyncClient, domain: str) -> set[str]:
    try:
        r = await client.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=15.0)
        if r.status_code != 200 or "API count exceeded" in r.text:
            return set()
        text = r.text
    except httpx.HTTPError:
        return set()
    out: set[str] = set()
    for line in text.splitlines():
        host = line.split(",", 1)[0].strip().lower()
        if host and host.endswith(domain.lower()) and SUBDOMAIN_RE.match(host):
            out.add(host)
    return out


async def _src_rapiddns(client: httpx.AsyncClient, domain: str) -> set[str]:
    try:
        r = await client.get(f"https://rapiddns.io/subdomain/{domain}?full=1#result", timeout=15.0)
        if r.status_code != 200:
            return set()
        text = r.text
    except httpx.HTTPError:
        return set()
    out: set[str] = set()
    for m in re.finditer(rf"([a-zA-Z0-9\-_.]+\.{re.escape(domain)})", text, re.IGNORECASE):
        s = m.group(1).lower().strip()
        if SUBDOMAIN_RE.match(s):
            out.add(s)
    return out


async def _src_wayback(client: httpx.AsyncClient, domain: str) -> set[str]:
    try:
        r = await client.get(
            f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey",
            timeout=25.0,
        )
        if r.status_code != 200:
            return set()
        data = r.json()
    except (httpx.HTTPError, ValueError):
        return set()
    out: set[str] = set()
    for row in data[1:] if isinstance(data, list) and len(data) > 1 else []:
        url = row[0] if isinstance(row, list) and row else ""
        m = re.match(r"https?://([^/]+)/", url)
        if m:
            host = m.group(1).lower().split(":")[0]
            if host.endswith(domain.lower()) and SUBDOMAIN_RE.match(host):
                out.add(host)
    return out


SOURCES: list[tuple[str, Callable[[httpx.AsyncClient, str], Awaitable[set[str]]]]] = [
    ("crt.sh", _src_crtsh),
    ("alienvault", _src_otx),
    ("threatminer", _src_threatminer),
    ("hackertarget", _src_hackertarget),
    ("rapiddns", _src_rapiddns),
    ("wayback", _src_wayback),
]


async def enumerate_subdomains(
    domain: str, *, sources: list[str] | None = None, graph: AssetGraph | None = None,
) -> dict[str, set[str]]:
    """Параллельно опросить все источники. Возвращает словарь source→set(host).

    `sources=None` — все. Список имён — только эти.
    """
    chosen = SOURCES if sources is None else [(n, fn) for n, fn in SOURCES if n in sources]

    async with get_async_client() as client:
        tasks = [fn(client, domain) for _, fn in chosen]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    by_source: dict[str, set[str]] = {}
    all_hosts: set[str] = set()
    for (name, _), result in zip(chosen, results, strict=True):
        if isinstance(result, BaseException):
            by_source[name] = set()
            continue
        by_source[name] = result
        all_hosts |= result

    if graph is not None:
        root_id = Asset.make_id(AssetType.DOMAIN, domain)
        graph.add_asset(Asset(id=root_id, type=AssetType.DOMAIN, value=domain, discovered_by="subdomains"))
        for host in all_hosts:
            sub_id = Asset.make_id(AssetType.SUBDOMAIN, host)
            graph.add_asset(Asset(
                id=sub_id, type=AssetType.SUBDOMAIN, value=host,
                attributes={"sources": [s for s, hosts in by_source.items() if host in hosts]},
                discovered_by="subdomains",
            ))
            graph.add_edge(Edge(
                subject=sub_id, relation="subdomain_of", object=root_id, discovered_by="subdomains",
            ))

    by_source["_all"] = all_hosts
    return by_source
