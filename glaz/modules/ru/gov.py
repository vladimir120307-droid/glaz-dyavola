"""Российские госструктуры — fingerprints доменов.

Распознавание:
- `.gov.ru`, `.mil.ru`, `.gov.spb.ru`, `.mos.ru` и региональные `<region>.gov.ru`
- Госуслуги (gosuslugi.ru) и ЕСИА (esia.gosuslugi.ru) — ключевая авторизация
- Региональные правительства, муниципалитеты
- Раскрытие сведений (zakupki.gov.ru, bus.gov.ru, fedresurs.ru, regulation.gov.ru)

Каждое распознавание — Finding с разной severity:
- gov-домен сам по себе: INFO
- ЕСИА-интеграция: LOW (доп. attack-surface для credential phishing)
- ОФЗ-портал / закупки: INFO
"""
from __future__ import annotations

import re

from glaz.core.findings import Confidence, Finding, Severity

GOV_TLDS = {
    ".gov.ru": "Федеральный орган РФ",
    ".gov.spb.ru": "Правительство Санкт-Петербурга",
    ".mos.ru": "Правительство Москвы",
    ".mil.ru": "Минобороны РФ",
    ".kremlin.ru": "Президент РФ",
    ".duma.gov.ru": "Госдума РФ",
    ".council.gov.ru": "Совет Федерации",
    ".pravo.gov.ru": "Официальное опубликование правовых актов",
    ".gosuslugi.ru": "Госуслуги",
    ".roskomnadzor.ru": "РКН",
    ".nalog.ru": "ФНС",
    ".pfr.gov.ru": "СФР (бывш. ПФР)",
    ".sfr.gov.ru": "СФР",
    ".fns.gov.ru": "ФНС",
    ".fssp.gov.ru": "ФССП",
    ".fsb.ru": "ФСБ",
    ".mvd.ru": "МВД",
    ".cbr.ru": "ЦБ РФ",
    ".sudrf.ru": "Судебная система",
    ".arbitr.ru": "Арбитражная система",
    ".mid.ru": "МИД",
    ".rosreestr.ru": "Росреестр",
    ".rosreestr.gov.ru": "Росреестр",
    ".bus.gov.ru": "Госзакупки (бюджет)",
    ".zakupki.gov.ru": "Госзакупки 44/223-ФЗ",
    ".fedresurs.ru": "ЕФРСБ (банкротства)",
    ".regulation.gov.ru": "Раскрытие НПА",
}

ESIA_HINT_URLS = [
    "esia.gosuslugi.ru",
    "esia-portal.gosuslugi.ru",
    "/esia/auth",
    "id.gosuslugi.ru",
]


def classify_gov_domain(domain: str) -> tuple[bool, str | None]:
    """Возвращает (is_gov, label_or_None)."""
    d = domain.lower()
    for suffix, label in GOV_TLDS.items():
        if d == suffix.lstrip(".") or d.endswith(suffix):
            return True, label
    return False, None


def detect_esia_integration(html_or_url: str) -> bool:
    return any(h in html_or_url for h in ESIA_HINT_URLS)


def gov_findings_for_domain(domain: str, html: str | None = None) -> list[Finding]:
    out: list[Finding] = []
    is_gov, label = classify_gov_domain(domain)
    if is_gov:
        out.append(Finding(
            rule_id="RU_GOV_DOMAIN",
            title=f"{domain} принадлежит государственной структуре РФ",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            target=domain,
            module="ru.gov",
            description=f"Распознан как: {label}",
            evidence={"domain": domain, "label": label, "key": f"gov:{domain}"},
            tags=["ru", "gov", "info"],
        ))
    if html and detect_esia_integration(html):
        out.append(Finding(
            rule_id="RU_ESIA_INTEGRATION",
            title=f"{domain} интегрирован с ЕСИА (Госуслуги)",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            target=domain,
            module="ru.gov",
            description="ЕСИА — ключевой credential vector в РФ. Phishing на ЕСИА страницу — типичная атака.",
            evidence={"domain": domain, "key": f"esia:{domain}"},
            tags=["ru", "gov", "esia", "auth"],
        ))
    return out


def normalize_inn_egrul_ogrn(text: str) -> dict[str, list[str]]:
    """Извлечь из текста ИНН (10/12), ОГРН (13/15), ОГРНИП (15)."""
    return {
        "inn": list(set(re.findall(r"\b\d{10}\b|\b\d{12}\b", text))),
        "ogrn": list(set(re.findall(r"\b\d{13}\b|\b\d{15}\b", text))),
    }
