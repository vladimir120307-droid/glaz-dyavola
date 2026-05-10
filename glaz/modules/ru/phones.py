"""Парсинг RU-телефонов: формат, оператор (по DEF-коду), регион.

DEF-коды (мобильные первые 3 цифры после +7) — открытый справочник от
Россвязи. Здесь — короткая выжимка по основным операторам и регионам.
Источник полного справочника: Минцифры (открытые данные).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# DEF-коды → оператор. Не полный, но покрывает 95% мобильных.
# Полная таблица в spec/abc-3xx.csv (см. https://opendata.digital.gov.ru/)
MOBILE_OPERATOR_PREFIXES = {
    "МТС": ["910", "911", "912", "913", "914", "915", "916", "917", "918", "919",
            "980", "981", "982", "983", "984", "985", "987", "988", "989"],
    "МегаФон": ["920", "921", "922", "923", "924", "925", "926", "927", "928", "929",
                "930", "931", "932", "933", "934", "936", "937", "938", "999"],
    "Билайн": ["903", "905", "906", "909", "951", "953", "960", "961", "962", "963",
               "964", "965", "966", "967", "968"],
    "Tele2": ["900", "902", "904", "908", "950", "952", "977", "991", "992", "993",
              "994", "995", "996", "997"],
    "Yota": ["999"],  # пересекается с МегаФон, ставится последним
    "Tinkoff Mobile": ["977"],  # MVNO Tele2
    "СберМобайл": ["958"],
    "VK Мобайл": ["996"],  # MVNO Tele2
}

# Стационарные коды — крупные регионы
LANDLINE_REGION_PREFIXES = {
    "495": "Москва",
    "499": "Москва",
    "498": "Московская область",
    "812": "Санкт-Петербург",
    "813": "Ленинградская область",
    "473": "Воронеж",
    "843": "Казань",
    "861": "Краснодар",
    "863": "Ростов-на-Дону",
    "351": "Челябинск",
    "342": "Пермь",
    "343": "Екатеринбург",
    "381": "Омск",
    "383": "Новосибирск",
    "391": "Красноярск",
    "423": "Владивосток",
    "831": "Нижний Новгород",
    "846": "Самара",
    "347": "Уфа",
}


@dataclass
class PhoneInfo:
    raw: str
    e164: str | None
    type: str  # mobile / landline / unknown
    country: str
    operator: str | None
    region: str | None
    valid: bool


def normalize_ru(raw: str) -> str | None:
    """Привести к E.164 (+7XXXXXXXXXX). Возвращает None если не RU."""
    digits = re.sub(r"\D", "", raw)
    if not digits:
        return None
    if digits.startswith("8") and len(digits) == 11:
        digits = "7" + digits[1:]
    if digits.startswith("7") and len(digits) == 11:
        return "+" + digits
    if len(digits) == 10:
        return "+7" + digits
    return None


def parse_phone(raw: str) -> PhoneInfo:
    """Распарсить RU-номер: формат, оператор/регион."""
    e164 = normalize_ru(raw)
    if not e164:
        return PhoneInfo(raw=raw, e164=None, type="unknown", country="?", operator=None, region=None, valid=False)

    nsn = e164[2:]  # без +7
    def_code = nsn[:3]

    # Mobile: DEF в 9XX
    if def_code.startswith("9"):
        operator = None
        for op, codes in MOBILE_OPERATOR_PREFIXES.items():
            if def_code in codes:
                operator = op
                break
        return PhoneInfo(
            raw=raw, e164=e164, type="mobile", country="RU",
            operator=operator, region=None, valid=True,
        )

    # Landline
    region = LANDLINE_REGION_PREFIXES.get(def_code)
    return PhoneInfo(
        raw=raw, e164=e164, type="landline" if region else "unknown",
        country="RU", operator=None, region=region, valid=region is not None,
    )
