"""Яндекс OSINT-footprint.

Что цепляем из открытых источников:
- Yandex Metrika ID на главной странице (счётчик трекинга)
- Яндекс.Карты — публичная карточка организации по запросу
- Yandex CDN/инфра — `*.yandex-cloud.com`, `*.cdn.yandex.net`
- DNS-MX → mail.yandex.ru = бизнес-почта на Яндексе

Все методы — пассивный GET'ы публичных страниц.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

import httpx


@dataclass
class YandexFootprint:
    domain: str
    metrika_ids: list[str]
    has_yandex_mail: bool
    has_yandex_cdn: bool
    notes: list[str]


METRIKA_RE = re.compile(r"(?:ym\(|yaCounter|Metrika.*?id\s*[:=]\s*)['\"]?(\d{6,10})", re.IGNORECASE)


def find_metrika(html: str) -> list[str]:
    """Найти Yandex.Metrika counter ID на странице."""
    return sorted(set(METRIKA_RE.findall(html)))


def fingerprint_yandex(domain: str) -> YandexFootprint:
    """Собрать яндекс-фингерпринт: метрика + почта + CDN."""
    notes: list[str] = []
    metrika: list[str] = []
    has_mail = False
    has_cdn = False

    try:
        with httpx.Client(timeout=10.0, follow_redirects=True) as client:
            r = client.get(f"https://{domain}",
                           headers={"User-Agent": "Mozilla/5.0 (compatible; glaz-dyavola)"})
            if r.status_code == 200:
                metrika = find_metrika(r.text)
                if metrika:
                    notes.append(f"Yandex.Metrika ID: {', '.join(metrika)}")
                if "yandex-cloud.com" in r.text or "cdn.yandex.net" in r.text:
                    has_cdn = True
                    notes.append("Используется Yandex Cloud / CDN")
    except httpx.HTTPError as e:
        notes.append(f"main page fetch failed: {e}")

    # MX-проверка
    try:
        from glaz.modules.dns.passive import get_records
        mx = get_records(domain, ("MX",)).get("MX", [])
        for record in mx:
            if "yandex" in record.lower() or "mail.yandex" in record.lower():
                has_mail = True
                notes.append(f"Бизнес-почта на Яндексе: {record}")
                break
    except Exception as e:  # noqa: BLE001
        notes.append(f"MX lookup failed: {e}")

    return YandexFootprint(
        domain=domain, metrika_ids=metrika,
        has_yandex_mail=has_mail, has_yandex_cdn=has_cdn,
        notes=notes,
    )


def metrika_overlap_search(metrika_id: str) -> list[str]:
    """Поиск других сайтов с тем же Metrika ID — общая инфраструктура / общий владелец.

    Используем PublicWWW-style эвристики через простой Google-dork (без API).
    Возвращает пустой список — это stub: для реального поиска нужен PublicWWW
    или BuiltWith API.
    """
    # Stub. Реализовать через PublicWWW когда будет ключ.
    return []
