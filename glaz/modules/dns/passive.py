"""DNS-разведка: пассивный сбор записей через trusted-resolver'ы.

Используем dnspython с явными resolver'ами (Cloudflare 1.1.1.1 / Quad9 9.9.9.9 /
Google 8.8.8.8) — не дёргаем рекурсор провайдера.
"""
from __future__ import annotations

from typing import Any

import dns.exception
import dns.resolver
import dns.reversename

from glaz.core.asset_graph import Asset, AssetGraph, AssetType, Edge
from glaz.core.findings import Confidence, Finding, Severity

TRUSTED_RESOLVERS = ["1.1.1.1", "9.9.9.9", "8.8.8.8"]
RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA")


def _make_resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = TRUSTED_RESOLVERS
    r.timeout = 4.0
    r.lifetime = 8.0
    return r


def get_records(domain: str, rtypes: tuple[str, ...] = RECORD_TYPES) -> dict[str, list[str]]:
    """Получить набор DNS-записей. Пустые/NXDOMAIN сворачиваются в пустые списки."""
    r = _make_resolver()
    out: dict[str, list[str]] = {}
    for rt in rtypes:
        try:
            ans = r.resolve(domain, rt, raise_on_no_answer=False)
            out[rt] = sorted({rdata.to_text() for rdata in ans})
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout, dns.resolver.NoAnswer):
            out[rt] = []
    return out


def reverse_lookup(ip: str) -> list[str]:
    r = _make_resolver()
    try:
        rev = dns.reversename.from_address(ip)
        ans = r.resolve(rev, "PTR")
        return sorted({rd.to_text().rstrip(".") for rd in ans})
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return []


def dns_passive_scan(domain: str, graph: AssetGraph | None = None) -> tuple[dict[str, Any], list[Finding]]:
    """Пассивный DNS-скан с интеграцией в asset_graph + базовые находки.

    Returns:
        (records, findings) — словарь по типам записей и список находок (например,
        отсутствие DNSSEC, открытый wildcard, и т.д.).
    """
    records = get_records(domain)
    findings: list[Finding] = []

    if graph is not None:
        domain_id = Asset.make_id(AssetType.DOMAIN, domain)
        graph.add_asset(Asset(
            id=domain_id, type=AssetType.DOMAIN, value=domain,
            attributes={"records": records}, discovered_by="dns",
        ))
        for ip in records.get("A", []) + records.get("AAAA", []):
            ip_id = Asset.make_id(AssetType.IP, ip)
            graph.add_asset(Asset(id=ip_id, type=AssetType.IP, value=ip, discovered_by="dns"))
            graph.add_edge(Edge(subject=domain_id, relation="resolves_to", object=ip_id, discovered_by="dns"))

    # DNSSEC — простейший индикатор
    try:
        r = _make_resolver()
        ans = r.resolve(domain, "DNSKEY", raise_on_no_answer=False)
        has_dnssec = bool(list(ans))
    except dns.exception.DNSException:
        has_dnssec = False

    if not has_dnssec:
        findings.append(Finding(
            rule_id="DNS_NO_DNSSEC", title=f"DNSSEC не настроен для {domain}",
            severity=Severity.LOW, confidence=Confidence.HIGH,
            target=domain, module="dns",
            description="Зона не публикует DNSKEY — DNSSEC не активен. Это не критично, но MITM на DNS-уровне не детектится.",
            evidence={"domain": domain, "key": "no_dnssec"},
            tags=["dns", "dnssec"],
        ))

    return records, findings
