"""Passive DNS — историческое разрешение хостов.

Источники без API-ключа:
- AlienVault OTX (passive_dns)
- crt.sh (CT logs дают IP-history через certs)
- HackerTarget (rate-limited)

Возвращает уникальные пары (host, ip, source).
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass

import httpx

from glaz.utils.http import get_async_client


@dataclass
class PdnsRecord:
    host: str
    ip: str | None
    rrtype: str
    first_seen: str | None
    last_seen: str | None
    source: str


async def _src_otx(client: httpx.AsyncClient, domain: str) -> list[PdnsRecord]:
    try:
        r = await client.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            timeout=20.0,
        )
        if r.status_code != 200:
            return []
        data = r.json()
    except (httpx.HTTPError, ValueError):
        return []
    out: list[PdnsRecord] = []
    for it in data.get("passive_dns", []):
        out.append(PdnsRecord(
            host=it.get("hostname", "").lower(),
            ip=it.get("address"),
            rrtype=it.get("record_type", "A"),
            first_seen=it.get("first"),
            last_seen=it.get("last"),
            source="otx",
        ))
    return out


async def _src_hackertarget(client: httpx.AsyncClient, domain: str) -> list[PdnsRecord]:
    try:
        r = await client.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=15.0)
        if r.status_code != 200 or "API count exceeded" in (r.text or ""):
            return []
    except httpx.HTTPError:
        return []
    out: list[PdnsRecord] = []
    for line in (r.text or "").splitlines():
        parts = line.split(",", 1)
        if len(parts) == 2:
            host, ip = parts
            out.append(PdnsRecord(
                host=host.lower(),
                ip=ip.strip(),
                rrtype="A",
                first_seen=None, last_seen=None,
                source="hackertarget",
            ))
    return out


async def _src_crtsh(client: httpx.AsyncClient, domain: str) -> list[PdnsRecord]:
    """CT logs не дают IP, но дают исторические host'ы → ассоциация."""
    try:
        r = await client.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=20.0)
        if r.status_code != 200:
            return []
        data = r.json()
    except (httpx.HTTPError, ValueError):
        return []
    out: list[PdnsRecord] = []
    seen_hosts: set[str] = set()
    for entry in data:
        for nv in (entry.get("name_value") or "").split("\n"):
            host = nv.strip().lower()
            if host and not host.startswith("*.") and host.endswith(domain.lower()):
                if host in seen_hosts:
                    continue
                seen_hosts.add(host)
                out.append(PdnsRecord(
                    host=host, ip=None, rrtype="A",
                    first_seen=entry.get("not_before"),
                    last_seen=entry.get("not_after"),
                    source="crtsh",
                ))
    return out


async def passive_dns_lookup(domain: str) -> list[PdnsRecord]:
    """Запустить все источники параллельно и слить."""
    async with get_async_client() as client:
        a, b, c = await asyncio.gather(
            _src_otx(client, domain),
            _src_hackertarget(client, domain),
            _src_crtsh(client, domain),
            return_exceptions=False,
        )
    return [*a, *b, *c]
