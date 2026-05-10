"""Common-prefix sweep — проверка типичных корпоративных префиксов:
admin., dev., staging., api., test., qa., uat., portal., и т.д.

Используется как дополнение к crt.sh + passive sources — иногда DNS-запись
есть, но в CT-логах не появилась (внутренние/недавние).

Не делает brute-force — только список из 100+ заранее известных корп-префиксов.
"""
from __future__ import annotations

import asyncio

import dns.exception
import dns.resolver

from glaz.core.asset_graph import Asset, AssetGraph, AssetType, Edge
from glaz.modules.dns.passive import _make_resolver

# 120 типичных корп-префиксов, упорядочены по частоте встречаемости
COMMON_PREFIXES: list[str] = [
    # Топ-20 (топ-tier по встречаемости)
    "www", "mail", "api", "admin", "dev", "staging", "test", "portal", "vpn", "remote",
    "smtp", "imap", "pop", "ns1", "ns2", "mx", "mx1", "mx2", "ftp", "blog",

    # Среды
    "prod", "production", "preprod", "qa", "uat", "demo", "sandbox", "lab", "labs",
    "internal", "private", "intranet", "extranet",

    # Auth / IAM
    "auth", "sso", "login", "oauth", "ldap", "ad", "idp", "sts", "token", "accounts",
    "okta", "adfs",

    # API/Doc
    "graphql", "v1", "v2", "v3", "docs", "swagger", "openapi", "spec",

    # CI/CD / git
    "git", "ci", "cd", "jenkins", "gitlab", "github", "bitbucket", "argocd", "spinnaker",

    # Cloud / контейнеры
    "kube", "k8s", "kubernetes", "etcd", "consul", "vault", "registry", "harbor",
    "docker", "ecr",

    # Web app
    "app", "web", "shop", "store", "checkout", "pay", "payment", "secure", "members",
    "my", "account", "user", "users", "profile", "billing", "support", "help",
    "kb", "faq", "wiki", "confluence", "jira", "issues",

    # Аналитика / мониторинг
    "stats", "metrics", "monitor", "monitoring", "grafana", "kibana", "elastic", "logs",
    "syslog", "alerts", "prometheus", "datadog", "sentry", "newrelic",

    # Storage / DB
    "s3", "static", "media", "cdn", "img", "files", "assets", "uploads", "downloads",
    "db", "mysql", "postgres", "redis", "mongo", "cassandra", "kafka", "rabbitmq",

    # Backup / mgmt
    "backup", "old", "old-www", "archive", "manage", "manager", "console", "control",
    "cpanel", "webmail",

    # Мобильные
    "m", "mobile", "ios", "android",

    # Региональные/локализация
    "ru", "us", "eu", "asia", "uk", "de",
]


def _resolve_sync(name: str, rtype: str) -> bool:
    r = _make_resolver()
    try:
        ans = r.resolve(name, rtype, raise_on_no_answer=False)
        return bool(list(ans))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return False


async def _check_one(domain: str) -> bool:
    """Проверить разрешается ли A/AAAA запись."""
    loop = asyncio.get_event_loop()
    for rt in ("A", "AAAA"):
        if await loop.run_in_executor(None, _resolve_sync, domain, rt):
            return True
    return False


async def sweep(domain: str, *, prefixes: list[str] | None = None,
                workers: int = 32, graph: AssetGraph | None = None) -> list[str]:
    """Проверить N корп-префиксов перед `domain`. Возвращает список существующих хостов."""
    use_prefixes = prefixes or COMMON_PREFIXES
    candidates = [f"{p}.{domain}" for p in use_prefixes]

    sem = asyncio.Semaphore(workers)

    async def _bounded(name: str) -> tuple[str, bool]:
        async with sem:
            return name, await _check_one(name)

    results = await asyncio.gather(*[_bounded(c) for c in candidates])
    found = [name for name, ok in results if ok]

    if graph is not None:
        root_id = Asset.make_id(AssetType.DOMAIN, domain)
        graph.add_asset(Asset(id=root_id, type=AssetType.DOMAIN, value=domain,
                              discovered_by="subdomains.sweep"))
        for host in found:
            sub_id = Asset.make_id(AssetType.SUBDOMAIN, host)
            graph.add_asset(Asset(id=sub_id, type=AssetType.SUBDOMAIN, value=host,
                                  attributes={"source": "common-prefix-sweep"},
                                  discovered_by="subdomains.sweep"))
            graph.add_edge(Edge(subject=sub_id, relation="subdomain_of",
                                object=root_id, discovered_by="subdomains.sweep"))

    return found
