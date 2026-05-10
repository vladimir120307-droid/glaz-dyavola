"""Русскоязычный OSINT-контур: ЕГРЮЛ/ФНС, VK, Яндекс, Telegram, RU-банки.

Главное преимущество `Глаз Дьявола` относительно западных OSINT-тулзов —
покрытие RU-сегмента из коробки.
"""
from glaz.modules.ru.banks import detect_bank_sso, lookup_bic, parse_card_iin
from glaz.modules.ru.egrul import lookup_by_inn, search_org
from glaz.modules.ru.fssp import search_individual, search_legal_entity
from glaz.modules.ru.gov import classify_gov_domain, gov_findings_for_domain
from glaz.modules.ru.phones import parse_phone
from glaz.modules.ru.telegram import lookup_username as tg_lookup_username
from glaz.modules.ru.vk import vk_resolve_screen_name
from glaz.modules.ru.yandex import fingerprint_yandex

__all__ = [
    "lookup_by_inn", "search_org",
    "parse_phone",
    "vk_resolve_screen_name",
    "search_individual", "search_legal_entity",
    "tg_lookup_username",
    "fingerprint_yandex",
    "lookup_bic", "detect_bank_sso", "parse_card_iin",
    "classify_gov_domain", "gov_findings_for_domain",
]
