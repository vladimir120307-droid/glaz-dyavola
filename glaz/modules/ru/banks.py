"""RU-банки: identity-fingerprints + БИК-справочник.

Что покрывает:
- БИК → название банка (статический справочник 50 крупнейших)
- DNS-fingerprint типичных SSO/IDP-доменов RU-банков (Сбер ID, Тинькофф ID,
  ВТБ Онлайн, Альфа SSO)
- Распознавание SSO-эндпоинтов из URL'ов / HTML
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# Топ-50 БИК → банк (короткая выжимка). Полный справочник — у ЦБ.
BIC_DIRECTORY: dict[str, str] = {
    "044525225": "ПАО Сбербанк",
    "044525974": "АО Тинькофф Банк",
    "044525187": "Банк ВТБ (ПАО)",
    "044525593": "АО Альфа-Банк",
    "044525700": "Банк ГПБ (АО) / Газпромбанк",
    "044525716": "ПАО МКБ / Московский Кредитный Банк",
    "044525555": "АО Райффайзенбанк",
    "044525440": "ПАО РОСБАНК",
    "044525545": "ПАО Промсвязьбанк",
    "044525411": "ПАО Совкомбанк",
    "044525823": "АО ЮниКредит Банк",
    "044525272": "АО Россельхозбанк",
    "044525659": "АО ОТП Банк",
    "044525432": "ПАО Банк Уралсиб",
    "044525214": "ПАО Банк ФК Открытие",
    "044525101": "АО Банк ДОМ.РФ",
    "044525632": "АО Хоум Кредит энд Финанс Банк",
    "044525249": "ПАО Совкомбанк (бывш. Восточный Экспресс Банк)",
    "044525974_": "Тинькофф (старый БИК)",
}

BANK_SSO_DOMAINS: dict[str, list[str]] = {
    "Сбер": ["online.sberbank.ru", "id.sber.ru", "esia.sberbank.ru"],
    "Тинькофф": ["www.tinkoff.ru", "id.tinkoff.ru", "secure.tinkoff.ru"],
    "ВТБ": ["online.vtb.ru", "id.vtb.ru"],
    "Альфа-Банк": ["online.alfabank.ru", "id.alfabank.ru", "click.alfabank.ru"],
    "Газпромбанк": ["online.gazprombank.ru"],
    "Райффайзен": ["online.raiffeisen.ru", "auth.raiffeisen.ru"],
}


@dataclass
class BankInfo:
    bic: str
    name: str | None


def lookup_bic(bic: str) -> BankInfo:
    """БИК → название. Возвращает BankInfo даже если не нашли (name=None)."""
    bic = bic.strip()
    return BankInfo(bic=bic, name=BIC_DIRECTORY.get(bic))


def detect_bank_sso(html_or_url: str) -> list[str]:
    """Распознать какие RU-банки фигурируют в HTML или URL (по SSO-доменам)."""
    found: list[str] = []
    for bank, domains in BANK_SSO_DOMAINS.items():
        for d in domains:
            if d in html_or_url:
                found.append(bank)
                break
    return sorted(set(found))


def parse_card_iin(card_number: str) -> dict[str, str | None]:
    """По первым 6 цифрам (BIN/IIN) определить банк-эмитент по короткой таблице.

    Это эвристика: полный BIN-справочник у MasterCard/Visa.
    """
    digits = re.sub(r"\D", "", card_number)
    if len(digits) < 6:
        return {"bin": None, "scheme": None, "issuer": None}
    bin_ = digits[:6]
    scheme = None
    # МИР проверяем первым — её BIN-диапазон попадает внутрь Mastercard 2-series,
    # без specifity-первого порядка он бы перехватился MC-веткой.
    if digits[:4] in ("2200", "2201", "2202", "2203", "2204"):
        scheme = "МИР"
    elif digits[0] == "4":
        scheme = "VISA"
    elif digits[0] == "5":
        scheme = "Mastercard"
    elif digits[0] == "2" and digits[1] in "1234567":
        scheme = "Mastercard (2-series)"
    elif digits[:2] == "62":
        scheme = "UnionPay"
    elif digits[0] == "3":
        scheme = "AmEx" if digits[1] in "47" else "JCB/Diners"

    # Очень короткая таблица популярных RU BIN'ов
    issuer_bin: dict[str, str] = {
        "427901": "Сбер VISA Classic",
        "427683": "Сбер VISA Gold",
        "521178": "Сбер MC Standard",
        "548409": "Тинькофф MC Black",
        "553420": "Тинькофф MC Black",
        "521324": "ВТБ MC",
        "415428": "Альфа VISA",
        "548673": "Альфа MC",
        "220070": "МИР Сбер",
        "220015": "МИР ВТБ",
    }
    return {"bin": bin_, "scheme": scheme, "issuer": issuer_bin.get(bin_)}
