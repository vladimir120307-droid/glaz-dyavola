"""Тесты people-OSINT: генерация email + транслитерация."""
from __future__ import annotations

from glaz.modules.people.email_perm import (
    generate_email_permutations,
    infer_pattern,
    transliterate,
)


def test_translit_basic() -> None:
    assert transliterate("Иван") == "ivan"
    assert transliterate("Сергей") == "sergey"
    assert transliterate("Юлия") == "yuliya"


def test_translit_ascii_passthrough() -> None:
    assert transliterate("John") == "john"


def test_perm_basic_first_last() -> None:
    g = generate_email_permutations("John", "Doe", "example.com")
    addrs = [x.address for x in g]
    assert "john.doe@example.com" in addrs
    assert "jdoe@example.com" in addrs
    assert "j.doe@example.com" in addrs
    assert "doe.john@example.com" in addrs


def test_perm_weighted_order() -> None:
    g = generate_email_permutations("John", "Doe", "example.com")
    # first.last должен идти первым (вес 1.0)
    assert g[0].address == "john.doe@example.com"
    assert g[0].weight == 1.0


def test_perm_translit_ru() -> None:
    g = generate_email_permutations("Иван", "Петров", "корп.ru")
    addrs = {x.address for x in g}
    assert "ivan.petrov@корп.ru" in addrs


def test_perm_invalid_inputs() -> None:
    assert generate_email_permutations("", "Doe", "example.com") == []
    assert generate_email_permutations("John", "", "example.com") == []
    assert generate_email_permutations("John", "Doe", "") == []


def test_infer_pattern_first_last() -> None:
    p = infer_pattern("john.doe@example.com", "John", "Doe")
    assert p == "{first}.{last}@example.com"


def test_infer_pattern_initial() -> None:
    p = infer_pattern("jdoe@corp.io", "John", "Doe")
    assert p == "{f}{last}@corp.io"


def test_infer_pattern_unknown() -> None:
    # Странный паттерн — не определяется
    p = infer_pattern("weird-email-format@x.com", "John", "Doe")
    assert p is None
