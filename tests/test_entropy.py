from glaz.utils.entropy import shannon_entropy


def test_empty() -> None:
    assert shannon_entropy("") == 0.0


def test_single_char() -> None:
    assert shannon_entropy("a") == 0.0


def test_low_entropy_repeated() -> None:
    assert shannon_entropy("aaaaaaaaaa") == 0.0


def test_high_entropy_random_b64() -> None:
    s = "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789+/="
    assert shannon_entropy(s) > 4.5


def test_hex_entropy() -> None:
    s = "0123456789abcdef" * 4
    e = shannon_entropy(s)
    # 16 символов, равномерное распределение → entropy = 4.0
    assert 3.9 < e < 4.1


def test_natural_text_lower_entropy() -> None:
    text = "the quick brown fox jumps over the lazy dog"
    # Природный текст обычно <4.5
    assert shannon_entropy(text) < 4.5
