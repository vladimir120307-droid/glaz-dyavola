from glaz.modules.ru.phones import normalize_ru, parse_phone


def test_normalize_8_format() -> None:
    assert normalize_ru("89261234567") == "+79261234567"


def test_normalize_plus7_format() -> None:
    assert normalize_ru("+7 (926) 123-45-67") == "+79261234567"


def test_normalize_7_format() -> None:
    assert normalize_ru("79261234567") == "+79261234567"


def test_normalize_short_invalid() -> None:
    assert normalize_ru("123") is None


def test_normalize_empty() -> None:
    assert normalize_ru("") is None


def test_parse_mts() -> None:
    info = parse_phone("+79161234567")
    assert info.valid
    assert info.type == "mobile"
    assert info.operator == "МТС"


def test_parse_megafon() -> None:
    info = parse_phone("+79261234567")
    assert info.valid
    assert info.type == "mobile"
    assert info.operator == "МегаФон"


def test_parse_moscow_landline() -> None:
    info = parse_phone("+74951234567")
    assert info.valid
    assert info.type == "landline"
    assert info.region == "Москва"


def test_parse_spb_landline() -> None:
    info = parse_phone("+78121234567")
    assert info.valid
    assert info.region == "Санкт-Петербург"


def test_parse_invalid() -> None:
    info = parse_phone("hello")
    assert not info.valid
    assert info.e164 is None
