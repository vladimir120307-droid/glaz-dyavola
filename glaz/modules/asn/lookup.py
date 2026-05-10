"""ASN / netblock — lookup через бесплатные публичные сервисы.

Источники:
- Cymru DNS (origin.asn.cymru.com) — IP → ASN, бесплатный TXT-lookup
- bgp.tools — IP → ASN + netblock + name
- RIPEstat data API — netblock + announced prefixes

Не используем shodan/maxmind (платные). Всё бесплатно и без ключей.
"""
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, ip_address

import dns.exception
import dns.resolver
import httpx

from glaz.modules.dns.passive import _make_resolver
from glaz.utils.http import get_client


@dataclass
class AsnRecord:
    ip: str
    asn: int | None
    asn_name: str | None
    country: str | None
    netblock: str | None
    description: str | None


def _ipv4_reverse_octets(ip: str) -> str:
    addr = IPv4Address(ip)
    octets = str(addr).split(".")
    return ".".join(reversed(octets))


def _cymru_lookup(ip: str) -> tuple[int | None, str | None, str | None]:
    """Cymru DNS: lookup `<reversed-ip>.origin.asn.cymru.com` TXT.

    Формат ответа: `"ASN | CIDR | CC | RIR | YYYY-MM-DD"` (примерно).
    """
    try:
        rev = _ipv4_reverse_octets(ip)
    except ValueError:
        return None, None, None
    name = f"{rev}.origin.asn.cymru.com"
    r = _make_resolver()
    try:
        ans = r.resolve(name, "TXT", raise_on_no_answer=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return None, None, None
    for rd in ans:
        text = "".join(s.decode() if isinstance(s, bytes) else s for s in rd.strings)
        parts = [p.strip() for p in text.split("|")]
        if len(parts) >= 3:
            try:
                asn = int(parts[0].split()[0])
            except ValueError:
                asn = None
            cidr = parts[1] or None
            cc = parts[2] or None
            return asn, cidr, cc
    return None, None, None


def _cymru_asn_name(asn: int) -> str | None:
    """ASN → описание через `AS<num>.asn.cymru.com` TXT."""
    name = f"AS{asn}.asn.cymru.com"
    r = _make_resolver()
    try:
        ans = r.resolve(name, "TXT", raise_on_no_answer=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return None
    for rd in ans:
        text = "".join(s.decode() if isinstance(s, bytes) else s for s in rd.strings)
        parts = [p.strip() for p in text.split("|")]
        if len(parts) >= 5:
            return parts[-1]  # последний — обычно name
    return None


def asn_for_ip(ip: str) -> AsnRecord:
    """IP → ASN + netblock + AS-name."""
    try:
        ip_address(ip)
    except ValueError:
        return AsnRecord(ip=ip, asn=None, asn_name=None, country=None, netblock=None,
                         description="Invalid IP")

    asn, cidr, cc = _cymru_lookup(ip)
    asn_name = _cymru_asn_name(asn) if asn else None

    return AsnRecord(
        ip=ip, asn=asn, asn_name=asn_name, country=cc,
        netblock=cidr, description=asn_name,
    )


def ip_to_asn_bulk(ips: list[str]) -> list[AsnRecord]:
    """Несколько IP → ASN. Для большой пачки используется netcat-style bulk
    Cymru на TCP/43, но для простоты тут — последовательный DNS."""
    return [asn_for_ip(ip) for ip in ips]


def netblock_for_asn(asn: int) -> list[str]:
    """ASN → список announced prefixes через RIPEstat data API."""
    try:
        with get_client() as client:
            r = client.get(
                "https://stat.ripe.net/data/announced-prefixes/data.json",
                params={"resource": f"AS{asn}"},
                timeout=15.0,
            )
            if r.status_code != 200:
                return []
            data = r.json()
    except (httpx.HTTPError, ValueError):
        return []
    return [p.get("prefix") for p in (data.get("data") or {}).get("prefixes", [])
            if p.get("prefix")]
