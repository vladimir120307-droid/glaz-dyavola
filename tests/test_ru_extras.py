"""Тесты для расширенного RU-слоя: gov, banks, telegram, yandex (offline)."""
from __future__ import annotations

from glaz.modules.ru.banks import detect_bank_sso, lookup_bic, parse_card_iin
from glaz.modules.ru.gov import (
    classify_gov_domain,
    detect_esia_integration,
    gov_findings_for_domain,
    normalize_inn_egrul_ogrn,
)
from glaz.modules.ru.yandex import find_metrika

# ============== gov ==============

def test_classify_gov_kremlin() -> None:
    is_gov, label = classify_gov_domain("kremlin.ru")
    assert is_gov
    assert label is not None


def test_classify_gov_subdomain() -> None:
    is_gov, label = classify_gov_domain("portal.gov.ru")
    assert is_gov


def test_classify_mos_ru() -> None:
    is_gov, label = classify_gov_domain("data.mos.ru")
    assert is_gov
    assert "Москв" in label


def test_classify_non_gov() -> None:
    is_gov, _ = classify_gov_domain("yandex.ru")
    assert not is_gov


def test_esia_detection() -> None:
    assert detect_esia_integration("https://esia.gosuslugi.ru/login")
    assert detect_esia_integration("<a href='/esia/auth'>Войти</a>")
    assert not detect_esia_integration("regular page without auth")


def test_gov_findings() -> None:
    findings = gov_findings_for_domain("nalog.gov.ru")
    assert any(f.rule_id == "RU_GOV_DOMAIN" for f in findings)


def test_inn_ogrn_extract() -> None:
    text = "ИНН: 7707083893, ОГРН: 1027700132195, ИП ОГРНИП: 304500116000157"
    out = normalize_inn_egrul_ogrn(text)
    assert "7707083893" in out["inn"]
    assert "1027700132195" in out["ogrn"]


# ============== banks ==============

def test_bic_sber() -> None:
    info = lookup_bic("044525225")
    assert info.name and "Сбер" in info.name


def test_bic_unknown() -> None:
    info = lookup_bic("000000000")
    assert info.name is None


def test_detect_bank_sso() -> None:
    found = detect_bank_sso("Login at id.tinkoff.ru/oauth/authorize")
    assert "Тинькофф" in found

    found = detect_bank_sso("plain text without bank refs")
    assert found == []


def test_card_visa_classic() -> None:
    info = parse_card_iin("4279 0100 0000 0000")
    assert info["scheme"] == "VISA"
    assert info["bin"] == "427901"


def test_card_mir() -> None:
    info = parse_card_iin("2200 7012 3456 7890")
    assert info["scheme"] and "МИР" in info["scheme"]


def test_card_invalid_short() -> None:
    info = parse_card_iin("123")
    assert info["bin"] is None


# ============== telegram (regex layer only — без сетевого вызова) ==============

def test_telegram_username_regex() -> None:
    """Проверяем только синтаксический фильтр lookup_username."""
    from glaz.modules.ru.telegram import lookup_username
    # invalid форматы возвращают None мгновенно (без сети)
    assert lookup_username("ab") is None  # слишком короткий
    assert lookup_username("with-dash") is None  # дефис нельзя
    assert lookup_username("") is None


# ============== yandex ==============

def test_find_metrika() -> None:
    html = '''
    <script>
      ym(12345678, "init");
      yaCounter98765432.reachGoal('test');
    </script>
    '''
    ids = find_metrika(html)
    assert "12345678" in ids
    assert "98765432" in ids


def test_find_metrika_empty() -> None:
    assert find_metrika("just some html without metrika") == []
