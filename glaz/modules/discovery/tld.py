"""TLD-энумерация — для бренда `acme` проверяем acme.com, acme.net, acme.ru, ...

Полезно для нахождения родственных доменов (особенно squat-кандидатов и
региональных брендов).
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass

import dns.exception
import dns.resolver

from glaz.modules.dns.passive import _make_resolver

# Топ-30 TLD по проникновению + RU-регион
COMMON_TLDS = [
    "com", "net", "org", "io", "co", "app", "dev", "ai", "tech",
    "info", "biz", "us", "uk", "de", "fr", "es", "it", "nl", "ca",
    "ru", "su", "рф", "by", "ua", "kz",
    "cn", "jp", "kr", "in", "br",
    "me", "tv", "cc", "pro",
]


@dataclass
class TldHit:
    domain: str
    has_records: bool
    sample_records: list[str]


def _check_one(name: str) -> TldHit:
    """Простая проверка: A или MX или NS существуют."""
    r = _make_resolver()
    sample: list[str] = []
    has = False
    for rt in ("A", "MX", "NS"):
        try:
            ans = r.resolve(name, rt, raise_on_no_answer=False)
            recs = [rd.to_text() for rd in ans]
            if recs:
                has = True
                sample.extend(f"{rt}={rec}" for rec in recs[:2])
                break
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
            continue
    return TldHit(domain=name, has_records=has, sample_records=sample)


async def enumerate_tlds(brand: str, tlds: list[str] | None = None,
                         workers: int = 16) -> list[TldHit]:
    """Перебрать TLD'ы для бренда, проверить которые существуют.

    `brand` — это short label без TLD, e.g. `acme`. Мы сами добавим `.<tld>`.
    """
    brand = brand.lower().split(".")[0].strip()
    if not brand:
        return []
    use_tlds = tlds or COMMON_TLDS

    loop = asyncio.get_event_loop()
    sem = asyncio.Semaphore(workers)

    async def _one(tld: str) -> TldHit:
        async with sem:
            return await loop.run_in_executor(None, _check_one, f"{brand}.{tld}")

    results = await asyncio.gather(*[_one(t) for t in use_tlds])
    return [r for r in results if r.has_records]
