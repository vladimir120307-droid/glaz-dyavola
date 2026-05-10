"""Генерация типичных email-permutations по имени + домену.

Покрывает 12 наиболее распространённых корпоративных схем:
- first.last@ / firstlast@ / first_last@ / first-last@
- f.last@ / flast@ / firstl@
- last.first@ / lastfirst@ / last.f@
- first@ / last@
- + russian: first.last@ для кириллицы → транслит

Возвращает упорядоченный список с весами (вес = типичность).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# Простая транслитерация ru → en (ГОСТ 7.79-2000 без диакритики, упрощённо).
_TRANSLIT = {
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "yo",
    "ж": "zh", "з": "z", "и": "i", "й": "y", "к": "k", "л": "l", "м": "m",
    "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u",
    "ф": "f", "х": "kh", "ц": "ts", "ч": "ch", "ш": "sh", "щ": "sch", "ъ": "",
    "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya",
}


def transliterate(text: str) -> str:
    text = text.lower()
    out = []
    for c in text:
        if c in _TRANSLIT:
            out.append(_TRANSLIT[c])
        elif c.isalpha() or c.isspace() or c == "-":
            out.append(c)
    return "".join(out)


@dataclass
class EmailGuess:
    address: str
    weight: float  # 0.0..1.0 — насколько правдоподобен паттерн


def generate_email_permutations(
    first: str, last: str, domain: str, *,
    middle: str = "",
    include_translit: bool = True,
) -> list[EmailGuess]:
    """Сгенерировать список вероятных email-адресов.

    Имена приводятся к нижнему регистру, кириллица транслитерируется.
    Возвращается отсортированный по weight список (наиболее вероятные первые).
    """
    f = re.sub(r"[^a-zа-я-]", "", first.strip().lower())
    l = re.sub(r"[^a-zа-я-]", "", last.strip().lower())  # noqa: E741
    if not f or not l or not domain:
        return []
    domain = domain.strip().lower().lstrip("@")

    candidates: list[tuple[str, float]] = []

    def add_combo(local: str, weight: float) -> None:
        if local and "@" not in local:
            candidates.append((f"{local}@{domain}", weight))

    # Базовые формы
    add_combo(f"{f}.{l}", 1.00)            # first.last @ — самая частая
    add_combo(f"{f[0]}.{l}", 0.85)         # f.last @
    add_combo(f"{f[0]}{l}", 0.80)          # flast @
    add_combo(f"{f}{l}", 0.75)             # firstlast @
    add_combo(f"{f}_{l}", 0.65)            # first_last @
    add_combo(f"{f}-{l}", 0.55)            # first-last @
    add_combo(f"{l}.{f}", 0.55)            # last.first @ (типично для DE/FR корп)
    add_combo(f"{l}{f[0]}", 0.40)          # lastf @
    add_combo(f"{f}", 0.45)                # first @ — для маленьких компаний
    add_combo(f"{l}", 0.40)                # last @
    add_combo(f"{f}{l[0]}", 0.30)          # firstl @
    if middle:
        m = re.sub(r"[^a-zа-я-]", "", middle.strip().lower())
        if m:
            add_combo(f"{f}.{m[0]}.{l}", 0.50)  # first.m.last @ — RU частенько

    # Транслитерация — если хоть одна часть кириллица
    if include_translit and any(c in _TRANSLIT for c in f + l):
        f_lat = transliterate(f).replace(" ", "")
        l_lat = transliterate(l).replace(" ", "")
        if f_lat and l_lat:
            add_combo(f"{f_lat}.{l_lat}", 0.95)
            add_combo(f"{f_lat[0]}.{l_lat}", 0.80)
            add_combo(f"{f_lat[0]}{l_lat}", 0.75)
            add_combo(f"{f_lat}{l_lat}", 0.70)
            add_combo(f"{f_lat}_{l_lat}", 0.55)

    # Дедуп с сохранением максимального веса
    by_addr: dict[str, float] = {}
    for a, w in candidates:
        by_addr[a] = max(by_addr.get(a, 0.0), w)
    return [EmailGuess(addr, w) for addr, w in
            sorted(by_addr.items(), key=lambda kv: -kv[1])]


# Эвристика инференса формата по найденному примеру
def infer_pattern(known_email: str, first: str, last: str) -> str | None:
    """Если известен email одного сотрудника — определить корпоративный паттерн.

    Возвращает строку-плейсхолдер вида '{first}.{last}@example.com' или None.
    """
    f = first.strip().lower()
    l = last.strip().lower()  # noqa: E741
    if "@" not in known_email:
        return None
    local, domain = known_email.lower().split("@", 1)

    patterns: list[tuple[str, str]] = [
        (f"{f}.{l}", "{first}.{last}"),
        (f"{f[0]}.{l}", "{f}.{last}"),
        (f"{f[0]}{l}", "{f}{last}"),
        (f"{f}{l}", "{first}{last}"),
        (f"{f}_{l}", "{first}_{last}"),
        (f"{f}-{l}", "{first}-{last}"),
        (f"{l}.{f}", "{last}.{first}"),
        (f"{l}{f}", "{last}{first}"),
        (f, "{first}"),
        (l, "{last}"),
    ]
    for needle, template in patterns:
        if local == needle:
            return f"{template}@{domain}"
    return None
